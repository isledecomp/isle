#include "racestandsentity.h"

#include "act1state.h"
#include "isle.h"
#include "isle_actions.h"
#include "islepathactor.h"
#include "legoanimationmanager.h"
#include "legogamestate.h"
#include "legoomni.h"
#include "legoutils.h"
#include "legoworld.h"
#include "misc.h"
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(RaceStandsEntity, 0x68)

// FUNCTION: LEGO1 0x10015450
MxLong RaceStandsEntity::VTable0x50(MxParam& p_param)
{
	if (FUN_1003ef60()) {
		Act1State* state = (Act1State*) GameState()->GetState("Act1State");
		state->SetUnknown18(0);

		if (CurrentActor()->GetActorId() != GameState()->GetActorId()) {
			CurrentActor()->VTable0xe4();
		}

		Isle* isle = (Isle*) FindWorld(*g_isleScript, IsleScript::c__Isle);
		isle->SetDestLocation(LegoGameState::Area::e_racecarbuild);

		AnimationManager()->FUN_10061010(0);
		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
	}

	return 1;
}
