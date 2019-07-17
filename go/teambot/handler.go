package teambot

import (
	"fmt"

	"github.com/keybase/client/go/libkb"
	"github.com/keybase/client/go/protocol/keybase1"
	"github.com/keybase/client/go/teams"
)

// HandleNewTeambotKey clears the in-memory cache of the latest known
// generation so a bot will use new keys when created
func HandleNewTeambotKey(mctx libkb.MetaContext, teamID keybase1.TeamID,
	generation keybase1.TeambotKeyGeneration) (err error) {
	defer mctx.TraceTimed("HandleNewTeambotKey", func() error { return err })()

	keyer := mctx.G().GetTeambotBotKeyer()
	if keyer == nil {
		return fmt.Errorf("bot keyer not found")
	}
	keyer.PurgeCacheForTeam(mctx, teamID)
	mctx.G().NotifyRouter.HandleNewTeambotKey(mctx.Ctx(), teamID, generation)
	return nil
}

// HandleTeambotEKNeeded forces a teambot key to be generated since the bot does
// not have access. All team members are notified and race to publish the
// requested key.
func HandleTeambotKeyNeeded(mctx libkb.MetaContext, teamID keybase1.TeamID, botUID keybase1.UID,
	generation keybase1.TeambotKeyGeneration) (err error) {
	defer mctx.TraceTimed("HandleTeambotKeyNeeded", func() error { return err })()
	defer func() {
		mctx.G().NotifyRouter.HandleTeambotKeyNeeded(mctx.Ctx(), teamID, botUID, generation)
	}()

	keyer := mctx.G().GetTeambotMemberKeyer()
	if keyer == nil {
		return fmt.Errorf("member keyer not found")
	}

	team, err := teams.Load(mctx.Ctx(), mctx.G(), keybase1.LoadTeamArg{
		ID: teamID,
	})
	if err != nil {
		return err
	}
	var appKey keybase1.TeamApplicationKey
	// Bot user needs the latest key
	if generation == 0 {
		// clear our caches here so we can force publish a key
		keyer.PurgeCache(mctx)
		// only CHAT application is supported
		appKey, err = team.ApplicationKey(mctx.Ctx(), keybase1.TeamApplication_CHAT)
		if err != nil {
			return err
		}
	} else {
		// Bot needs a specific generation
		keyer.PurgeCacheAtGeneration(mctx, teamID, botUID, generation)
		appKey, err = team.ApplicationKeyAtGeneration(mctx.Ctx(), keybase1.TeamApplication_CHAT,
			keybase1.PerTeamKeyGeneration(generation))
		if err != nil {
			return err
		}
	}

	_, _, err = keyer.GetOrCreateTeambotKey(mctx, teamID, botUID.ToBytes(), appKey)
	return err
}
