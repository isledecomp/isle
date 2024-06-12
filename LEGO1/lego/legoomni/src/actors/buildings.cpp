#include "buildings.h"

#include "act2main_actions.h"
#include "act3.h"
#include "act3_actions.h"
#include "isle.h"
#include "isle_actions.h"
#include "islepathactor.h"
#include "legoact2.h"
#include "legoanimationmanager.h"
#include "legogamestate.h"
#include "legoutils.h"
#include "legoworld.h"
#include "misc.h"
#include "mxtransitionmanager.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(BeachHouseEntity, 0x68)
DECOMP_SIZE_ASSERT(GasStationEntity, 0x68)
DECOMP_SIZE_ASSERT(HospitalEntity, 0x68)
DECOMP_SIZE_ASSERT(InfoCenterEntity, 0x68)
DECOMP_SIZE_ASSERT(JailEntity, 0x68)
DECOMP_SIZE_ASSERT(PoliceEntity, 0x68)
DECOMP_SIZE_ASSERT(RaceStandsEntity, 0x68)

// FUNCTION: LEGO1 0x100150c0
MxLong InfoCenterEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	switch (GameState()->GetCurrentAct()) {
	case LegoGameState::Act::e_act1: {
		if (UserActor()->GetActorId() != GameState()->GetActorId()) {
			((IslePathActor*) UserActor())->Exit();
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

	AnimationManager()->FUN_10061010(FALSE);
	TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
	return 1;
}

// FUNCTION: LEGO1 0x100151d0
MxLong GasStationEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	if (FUN_1003ef60()) {
		Act1State* state = (Act1State*) GameState()->GetState("Act1State");

		if (state->GetUnknown18() != 8) {
			state->SetUnknown18(0);

			if (UserActor()->GetActorId() != GameState()->GetActorId()) {
				((IslePathActor*) UserActor())->Exit();
			}

			Isle* isle = (Isle*) FindWorld(*g_isleScript, IsleScript::c__Isle);
			isle->SetDestLocation(LegoGameState::Area::e_garage);

			AnimationManager()->FUN_10061010(FALSE);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x10015270
MxLong HospitalEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	if (FUN_1003ef60()) {
		Act1State* act1State = (Act1State*) GameState()->GetState("Act1State");

		if (act1State->GetUnknown18() != 10) {
			act1State->SetUnknown18(0);

			if (UserActor()->GetActorId() != GameState()->GetActorId()) {
				((IslePathActor*) UserActor())->Exit();
			}

			Isle* isle = (Isle*) FindWorld(*g_isleScript, IsleScript::c__Isle);
			isle->SetDestLocation(LegoGameState::Area::e_hospital);

			AnimationManager()->FUN_10061010(FALSE);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x10015310
MxLong PoliceEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	if (FUN_1003ef60()) {
		Act1State* state = (Act1State*) GameState()->GetState("Act1State");

		if (state->GetUnknown18() != 10) {
			state->SetUnknown18(0);

			if (UserActor()->GetActorId() != GameState()->GetActorId()) {
				((IslePathActor*) UserActor())->Exit();
			}

			Isle* isle = (Isle*) FindWorld(*g_isleScript, IsleScript::c__Isle);
			isle->SetDestLocation(LegoGameState::Area::e_police);

			AnimationManager()->FUN_10061010(FALSE);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x100153b0
MxLong BeachHouseEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	if (FUN_1003ef60()) {
		Act1State* state = (Act1State*) GameState()->GetState("Act1State");
		state->SetUnknown18(0);

		if (UserActor()->GetActorId() != GameState()->GetActorId()) {
			((IslePathActor*) UserActor())->Exit();
		}

		Isle* isle = (Isle*) FindWorld(*g_isleScript, IsleScript::c__Isle);
		isle->SetDestLocation(LegoGameState::Area::e_jetskibuild);

		AnimationManager()->FUN_10061010(FALSE);
		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
	}

	return 1;
}

// FUNCTION: LEGO1 0x10015450
MxLong RaceStandsEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	if (FUN_1003ef60()) {
		Act1State* state = (Act1State*) GameState()->GetState("Act1State");
		state->SetUnknown18(0);

		if (UserActor()->GetActorId() != GameState()->GetActorId()) {
			((IslePathActor*) UserActor())->Exit();
		}

		Isle* isle = (Isle*) FindWorld(*g_isleScript, IsleScript::c__Isle);
		isle->SetDestLocation(LegoGameState::Area::e_racecarbuild);

		AnimationManager()->FUN_10061010(FALSE);
		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
	}

	return 1;
}

// STUB: LEGO1 0x100154f0
MxLong JailEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10015520
MxLong CaveEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	// TODO
	return 0;
}
