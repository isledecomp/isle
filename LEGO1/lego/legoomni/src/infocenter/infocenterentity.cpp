#include "infocenterentity.h"

#include "act1state.h"
#include "act2main_actions.h"
#include "act3.h"
#include "act3_actions.h"
#include "act3state.h"
#include "isle.h"
#include "isle_actions.h"
#include "islepathactor.h"
#include "legoact2.h"
#include "legoact2state.h"
#include "legoanimationmanager.h"
#include "legogamestate.h"
#include "legoomni.h"
#include "legoutils.h"
#include "legoworld.h"
#include "misc.h"
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(InfoCenterEntity, 0x68)

// FUNCTION: LEGO1 0x100150c0
MxLong InfoCenterEntity::VTable0x50(MxParam& p_param)
{
	switch (GameState()->GetCurrentAct()) {
	case LegoGameState::Act::e_act1: {
		if (CurrentActor()->GetActorId() != GameState()->GetActorId()) {
			CurrentActor()->VTable0xe4();
		}

		Isle* isle = (Isle*) FindWorld(*g_isleScript, IsleScript::c__Isle);
		isle->FUN_10033350();
		isle->SetDestLocation(LegoGameState::Area::e_infomain);

		Act1State* act1state = (Act1State*) GameState()->GetState("Act1State");
		act1state->SetUnknown18(0);
		break;
	}
	case LegoGameState::Act::e_act2: {
		LegoAct2* act2 = (LegoAct2*) FindWorld(*g_act2mainScript, Act2mainScript::c__Act2Main);
		act2->SetUnknown0x1150(2);

		LegoAct2State* act2state = (LegoAct2State*) GameState()->GetState("LegoAct2State");
		if (act2state) {
			act2state->SetUnknown0x0c(0);
		}
		break;
	}
	case LegoGameState::Act::e_act3:
		Act3* act3 = (Act3*) FindWorld(*g_act3Script, Act3Script::c__Act3);
		act3->SetUnknown4270(2);
		break;
	}

	AnimationManager()->FUN_10061010(0);
	TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);

	return 1;
}
