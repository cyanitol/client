package teambot

import (
	"encoding/json"
	"fmt"

	"github.com/keybase/client/go/kbcrypto"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/client/go/teams"
)

const lruSize = 1000
const maxRetries = 5

type TeambotKeyError struct {
	inner      error
	generation keybase1.TeambotKeyGeneration
}

func newTeambotKeyError(inner error, generation keybase1.TeambotKeyGeneration) TeambotKeyError {
	return TeambotKeyError{
		inner:      inner,
		generation: generation,
	}
}

func (e TeambotKeyError) Error() string {
	return fmt.Sprintf("TeambotKeyError for generation: %d. %v", e.generation, e.inner)
}

func newTeambotSeedFromBytes(b []byte) (seed keybase1.Bytes32, err error) {
	if len(b) != libkb.NaclDHKeysize {
		err = fmt.Errorf("Wrong EkSeed len: %d != %d", len(b), libkb.NaclDHKeysize)
		return seed, err
	}
	copy(seed[:], b)
	return seed, nil
}

func deriveTeambotDHKey(seed keybase1.Bytes32) *libkb.NaclDHKeyPair {
	derived, err := libkb.DeriveFromSecret(seed, libkb.DeriveReasonTeambotKeyEncryption)
	if err != nil {
		panic("This should never fail: " + err.Error())
	}
	keypair, err := libkb.MakeNaclDHKeyPairFromSecret(derived)
	if err != nil {
		panic("This should never fail: " + err.Error())
	}
	return &keypair
}

func extractTeambotKeyMetadataFromSig(sig string) (*kbcrypto.NaclSigningKeyPublic, *keybase1.TeambotKeyMetadata, error) {
	signerKey, payload, _, err := kbcrypto.NaclVerifyAndExtract(sig)
	if err != nil {
		return signerKey, nil, err
	}

	parsedMetadata := keybase1.TeambotKeyMetadata{}
	if err = json.Unmarshal(payload, &parsedMetadata); err != nil {
		return signerKey, nil, err
	}
	return signerKey, &parsedMetadata, nil
}

// Verify that the blob is validly signed, and that the signing key is the
// given team's latest PTK, then parse its contents.
func verifyTeambotKeySigWithLatestPTK(mctx libkb.MetaContext, teamID keybase1.TeamID, sig string) (
	metadata *keybase1.TeambotKeyMetadata, wrongKID bool, err error) {
	defer mctx.TraceTimed("verifyTeambotSigWithLatestPTK", func() error { return err })()

	signerKey, metadata, err := extractTeambotKeyMetadataFromSig(sig)
	if err != nil {
		return nil, false, err
	}

	team, err := teams.Load(mctx.Ctx(), mctx.G(), keybase1.LoadTeamArg{
		ID: teamID,
	})
	if err != nil {
		return nil, false, err
	}

	// Verify the signing key corresponds to the latest PTK. We load the team's
	// from cache, but if the KID doesn't match, we try a forced reload to see
	// if the cache might've been stale. Only if the KID still doesn't match
	// after the reload do we complain.
	teamSigningKID, err := team.SigningKID(mctx.Ctx())
	if err != nil {
		return nil, false, err
	}
	if !teamSigningKID.Equal(signerKey.GetKID()) {
		// The latest PTK might be stale. Force a reload, then check this over again.
		team, err := teams.Load(mctx.Ctx(), mctx.G(), keybase1.LoadTeamArg{
			ID:          team.ID,
			ForceRepoll: true,
		})
		if err != nil {
			return nil, false, err
		}
		teamSigningKID, err = team.SigningKID(mctx.Ctx())
		if err != nil {
			return nil, false, err
		}
		// return the metdata with wrongKID=true
		if !teamSigningKID.Equal(signerKey.GetKID()) {
			return metadata, true, fmt.Errorf("teambotEK returned for PTK signing KID %s, but latest is %s",
				signerKey.GetKID(), teamSigningKID)
		}
	}

	// If we didn't short circuit above, then the signing key is correct.
	return metadata, false, nil
}