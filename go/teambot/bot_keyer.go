package teambot

import (
	"context"
	"fmt"
	"log"

	lru "github.com/hashicorp/golang-lru"
	"github.com/keybase/client/go/encrypteddb"
	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/clockwork"
)

const botKeyStorageVersion = 1

type BotKeyer struct {
	storeLocks, libLocks *libkb.LockTable
	lru                  *lru.Cache
	encryptedDB          *encrypteddb.EncryptedDB
	clock                clockwork.Clock
}

var _ libkb.TeambotBotKeyer = (*BotKeyer)(nil)

func NewBotKeyer(mctx libkb.MetaContext) *BotKeyer {
	keyFn := func(ctx context.Context) ([32]byte, error) {
		return encrypteddb.GetSecretBoxKey(ctx, mctx.G(), encrypteddb.DefaultSecretUI,
			libkb.EncryptionReasonContactsLocalStorage, "encrypting teambot keys cache")
	}
	dbFn := func(g *libkb.GlobalContext) *libkb.JSONLocalDb {
		return g.LocalDb
	}
	nlru, err := lru.New(lruSize)
	if err != nil {
		// lru.New only panics if size <= 0
		log.Panicf("Could not create lru cache: %v", err)
	}
	return &BotKeyer{
		encryptedDB: encrypteddb.New(mctx.G(), dbFn, keyFn),
		lru:         nlru,
		storeLocks:  &libkb.LockTable{},
		libLocks:    &libkb.LockTable{},
		clock:       clockwork.NewRealClock(),
	}
}

func (k *BotKeyer) SetClock(clock clockwork.Clock) {
	k.clock = clock
}

func (k *BotKeyer) lockKey(teamID keybase1.TeamID) string {
	return teamID.String()
}

func (k *BotKeyer) latestGenCacheKey(mctx libkb.MetaContext, teamID keybase1.TeamID) string {
	return fmt.Sprintf("%s-%s", teamID, mctx.G().Env.GetUID())
}

func (k *BotKeyer) cacheKey(mctx libkb.MetaContext, teamID keybase1.TeamID,
	generation keybase1.TeambotKeyGeneration) (string, error) {
	uv, err := mctx.G().GetMeUV(mctx.Ctx())
	if err != nil {
		return "", err
	}
	key := fmt.Sprintf("teambotKey-%s-%s-%d-%d", teamID, mctx.G().Env.GetUID(),
		uv.EldestSeqno, botKeyStorageVersion)
	return key, nil
}

func (k *BotKeyer) dbKey(cacheKey string) libkb.DbKey {
	return libkb.DbKey{
		Typ: libkb.DBTeambotKey,
		Key: cacheKey,
	}
}

func (k *BotKeyer) get(mctx libkb.MetaContext, teamID keybase1.TeamID, generation keybase1.TeambotKeyGeneration) (
	key keybase1.TeambotKey, err error) {
	defer mctx.TraceTimed(fmt.Sprintf("getBox#Get: teamID:%v, generation:%v", teamID, generation),
		func() error { return err })()

	lock := k.storeLocks.AcquireOnName(mctx.Ctx(), mctx.G(), k.lockKey(teamID))
	key, found, err := k.getLocked(mctx, teamID, generation)
	lock.Release(mctx.Ctx())
	if err != nil || found {
		return key, err
	}

	// no lock while we fetch
	return k.fetchAndStore(mctx, teamID, generation)
}

func (k *BotKeyer) getLocked(mctx libkb.MetaContext, teamID keybase1.TeamID,
	generation keybase1.TeambotKeyGeneration) (key keybase1.TeambotKey, found bool, err error) {
	boxKey, err := k.cacheKey(mctx, teamID, generation)
	if err != nil {
		return key, false, err
	}

	res, found := k.lru.Get(boxKey)
	if found {
		key, ok := res.(keybase1.TeambotKey)
		if !ok {
			return key, false, fmt.Errorf("unable to load teambotkey from cache found %T, expected %T", res, keybase1.TeambotKey{})
		}
		return key, false, nil
	}

	dbKey := k.dbKey(boxKey)
	found, err = k.encryptedDB.Get(mctx.Ctx(), dbKey, &key)
	if err != nil {
		return key, false, err
	}
	if !found {
		return keybase1.TeambotKey{}, false, nil
	}

	k.lru.Add(boxKey, key)
	return key, true, nil
}

func (k *BotKeyer) put(mctx libkb.MetaContext, teamID keybase1.TeamID,
	generation keybase1.TeambotKeyGeneration, key keybase1.TeambotKey) error {
	lock := k.storeLocks.AcquireOnName(mctx.Ctx(), mctx.G(), k.lockKey(teamID))
	defer lock.Release(mctx.Ctx())

	boxKey, err := k.cacheKey(mctx, teamID, generation)
	if err != nil {
		return err
	}
	dbKey := k.dbKey(boxKey)
	if err = k.encryptedDB.Put(mctx.Ctx(), dbKey, key); err != nil {
		return err
	}
	k.lru.Add(boxKey, key)
	return nil
}

func (k *BotKeyer) fetchAndStore(mctx libkb.MetaContext, teamID keybase1.TeamID, generation keybase1.TeambotKeyGeneration) (
	key keybase1.TeambotKey, err error) {
	defer mctx.TraceTimed(fmt.Sprintf("BotKeyer#fetchAndStore: teamID:%v, generation:%v", teamID, generation), func() error { return err })()

	boxed, err := k.fetch(mctx, teamID, generation)
	if err != nil {
		return key, err
	}
	key, err = k.unbox(mctx, boxed)
	if err != nil {
		return key, err
	}

	err = k.put(mctx, teamID, generation, key)
	return key, err
}

func (k *BotKeyer) unbox(mctx libkb.MetaContext, boxed keybase1.TeambotKeyBoxed) (
	key keybase1.TeambotKey, err error) {
	defer mctx.TraceTimed(fmt.Sprintf("BotKeyer#unbox: generation: %v",
		boxed.Metadata.Generation), func() error { return err })()

	pukring, err := mctx.G().GetPerUserKeyring(mctx.Ctx())
	if err != nil {
		return key, err
	}
	if err = pukring.Sync(mctx); err != nil {
		return key, err
	}
	encKey, err := pukring.GetEncryptionKeyByGenerationOrSync(mctx, boxed.Metadata.PukGeneration)
	if err != nil {
		return key, err
	}

	msg, _, err := encKey.DecryptFromString(boxed.Box)
	if err != nil {
		return key, newTeambotKeyError(err, boxed.Metadata.Generation)
	}

	seed, err := newTeambotSeedFromBytes(msg)
	if err != nil {
		return key, err
	}

	keypair := deriveTeambotDHKey(seed)
	if !keypair.GetKID().Equal(boxed.Metadata.Kid) {
		return key, fmt.Errorf("Failed to verify server given seed against signed KID %s",
			boxed.Metadata.Kid)
	}

	return keybase1.TeambotKey{
		Seed:     seed,
		Metadata: boxed.Metadata,
	}, nil
}

type TeambotKeyBoxedResponse struct {
	Result *struct {
		Box string `json:"box"`
		Sig string `json:"sig"`
	} `json:"result"`
}

func (k *BotKeyer) fetch(mctx libkb.MetaContext, teamID keybase1.TeamID,
	generation keybase1.TeambotKeyGeneration) (boxed keybase1.TeambotKeyBoxed, err error) {
	apiArg := libkb.APIArg{
		Endpoint:    "teambot/box",
		SessionType: libkb.APISessionTypeREQUIRED,
		Args: libkb.HTTPArgs{
			"team_id":      libkb.S{Val: string(teamID)},
			"generation":   libkb.U{Val: uint64(generation)},
			"is_ephemeral": libkb.B{Val: false},
		},
	}

	var resp TeambotKeyBoxedResponse
	res, err := mctx.G().GetAPI().Get(mctx, apiArg)
	if err != nil {
		return boxed, err
	}

	if err = res.Body.UnmarshalAgain(&resp); err != nil {
		return boxed, err
	}

	if resp.Result == nil {
		err = newTeambotKeyError(fmt.Errorf("missing box"), generation)
		return boxed, err
	}

	// Although we verify the signature is valid, it's possible that this key
	// was signed with a PTK that is not our latest and greatest. We allow this
	// when we are using this key for *decryption*. When getting a key for
	// *encryption* callers are responsible for verifying the signature is
	// signed by the latest PTK or requesting a new key. This logic currently
	// lives in teambot/bot_keyer.go#getLatestTeambotKey
	_, metadata, err := extractTeambotKeyMetadataFromSig(resp.Result.Sig)
	if err != nil {
		return boxed, err
	} else if metadata == nil { // shouldn't happen
		return boxed, fmt.Errorf("unable to fetch valid teambotKeyMetadata")
	}

	if generation != metadata.Generation {
		// sanity check that we got the right generation
		return boxed, fmt.Errorf("generation mismatch, expected:%d vs actual:%d",
			generation, metadata.Generation)
	}
	return keybase1.TeambotKeyBoxed{
		Box:      resp.Result.Box,
		Metadata: *metadata,
	}, nil
}

type TeambotKeyResponse struct {
	Result *struct {
		Sig string `json:"sig"`
	} `json:"result"`
}

func (k *BotKeyer) fetchLatestTeambotKey(mctx libkb.MetaContext, teamID keybase1.TeamID) (
	metadata *keybase1.TeambotKeyMetadata, wrongKID bool, err error) {
	defer mctx.TraceTimed("BotKeyer#fetchLatestTeambotKey", func() error { return err })()

	apiArg := libkb.APIArg{
		Endpoint:    "teambot/key",
		SessionType: libkb.APISessionTypeREQUIRED,
		Args: libkb.HTTPArgs{
			"team_id":      libkb.S{Val: string(teamID)},
			"is_ephemeral": libkb.B{Val: false},
		},
	}
	res, err := mctx.G().GetAPI().Get(mctx, apiArg)
	if err != nil {
		return nil, false, err
	}

	var parsedResponse TeambotKeyResponse
	if err = res.Body.UnmarshalAgain(&parsedResponse); err != nil {
		return nil, false, err
	}
	if parsedResponse.Result == nil {
		return nil, false, nil
	}

	return verifyTeambotKeySigWithLatestPTK(mctx, teamID, parsedResponse.Result.Sig)
}

func (k *BotKeyer) GetLatestTeambotKey(mctx libkb.MetaContext, teamID keybase1.TeamID) (key keybase1.TeambotKey, err error) {
	mctx = mctx.WithLogTag("GLTBK")
	defer mctx.TraceTimed(fmt.Sprintf("BotKeyer#GetLatestTeambotKey teamID: %v", teamID),
		func() error { return err })()

	lock := k.libLocks.AcquireOnName(mctx.Ctx(), mctx.G(), k.lockKey(teamID))
	defer lock.Release(mctx.Ctx())

	key, err = k.getLatestTeambotKeyLocked(mctx, teamID)
	if err != nil {
		switch err.(type) {
		case TeambotKeyError:
			// Ping team members to generate the latest key for us
			if err2 := NotifyTeambotKeyNeeded(mctx, teamID, 0); err2 != nil {
				mctx.Debug("Unable to NotifyTeambotKeyNeeded %v", err2)
			}
		}
		return key, err
	}
	return key, nil
}

func (k *BotKeyer) getLatestTeambotKeyLocked(mctx libkb.MetaContext, teamID keybase1.TeamID) (key keybase1.TeambotKey, err error) {
	cacheKey := k.latestGenCacheKey(mctx, teamID)
	entry, found := k.lru.Get(cacheKey)

	var latestGen keybase1.TeambotKeyGeneration
	if !found {
		// Let's see what the latest teambot key is. This verifies that the metadata
		// was signed by the latest PTK and otherwise fails with wrongKID set.
		metadata, wrongKID, err := k.fetchLatestTeambotKey(mctx, teamID)
		if metadata == nil {
			return key, newTeambotKeyError(fmt.Errorf("missing teambot key"), -1)
		} else if wrongKID {
			now := keybase1.ToTime(k.clock.Now())
			permitted, ctime, err := TeambotKeyWrongKIDPermitted(mctx, teamID,
				mctx.G().Env.GetUID(), metadata.Generation, now)
			if err != nil {
				return key, err
			}
			mctx.Debug("getLatestTeambotKey: wrongKID set, perrmited: %v, ctime: %v ", permitted, ctime)
			if !permitted {
				err = fmt.Errorf("Wrong KID, first seen at %v, now %v", ctime.Time(), now.Time())
				// TODO permanent vs transient err
				return key, newTeambotKeyError(err, metadata.Generation)
			}

			// Ping other team members to create the new key for us.
			if err = NotifyTeambotKeyNeeded(mctx, teamID, 0); err != nil {
				// Charge forward here, we'll try again next time we fetch this
				// key.
				mctx.Debug("Unable to notifyTeambotKeyNeeded %v", err)
			}
		} else if err != nil {
			return key, err
		}
		latestGen = metadata.Generation
	} else {
		var ok bool
		latestGen, ok = entry.(keybase1.TeambotKeyGeneration)
		if !ok {
			return key, fmt.Errorf("unable to cast cache value, found %T, expected %T",
				latestGen, keybase1.TeambotKeyGeneration(0))
		}
	}

	key, err = k.get(mctx, teamID, latestGen)
	if err != nil {
		return key, err
	}
	k.lru.Add(cacheKey, latestGen)
	return key, nil
}

func (k *BotKeyer) GetTeambotKeyAtGeneration(mctx libkb.MetaContext, teamID keybase1.TeamID,
	generation keybase1.TeambotKeyGeneration) (key keybase1.TeambotKey, err error) {
	mctx = mctx.WithLogTag("GTBK")
	defer mctx.TraceTimed(fmt.Sprintf("BotKeyer#GetLatestTeambotKey teamID: %v", teamID),
		func() error { return err })()
	key, err = k.get(mctx, teamID, generation)
	if err != nil {

		switch err.(type) {
		case TeambotKeyError:
			// Ping team members to generate the latest key for us
			if err2 := NotifyTeambotKeyNeeded(mctx, teamID, 0); err2 != nil {
				mctx.Debug("Unable to NotifyTeambotKeyNeeded %v", err2)
			}
		}
		return key, err
	}
	return key, nil
}

func (k *BotKeyer) PurgeCache(mctx libkb.MetaContext) {
	k.lru.Purge()
}

func (k *BotKeyer) PurgeCacheForTeam(mctx libkb.MetaContext, teamID keybase1.TeamID) {
	cacheKey := k.latestGenCacheKey(mctx, teamID)
	k.lru.Remove(cacheKey)
}

func (k *BotKeyer) OnLogout(mctx libkb.MetaContext) error {
	k.lru.Purge()
	return nil
}

func (k *BotKeyer) OnDbNuke(mctx libkb.MetaContext) error {
	k.lru.Purge()
	return nil
}
