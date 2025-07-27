#include "buildings.h"

#include "act2main_actions.h"
#include "act3.h"
#include "act3_actions.h"
#include "isle.h"
#include "isle_actions.h"
#include "islepathactor.h"
#include "legoact2.h"
#include "legoanimationmanager.h"
#include "legoeventnotificationparam.h"
#include "legogamestate.h"
#include "legoutils.h"
#include "legoworld.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxtransitionmanager.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(BeachHouseEntity, 0x68)
DECOMP_SIZE_ASSERT(GasStationEntity, 0x68)
DECOMP_SIZE_ASSERT(HospitalEntity, 0x68)
DECOMP_SIZE_ASSERT(InfoCenterEntity, 0x68)
DECOMP_SIZE_ASSERT(JailEntity, 0x68)
DECOMP_SIZE_ASSERT(PoliceEntity, 0x68)
DECOMP_SIZE_ASSERT(RaceStandsEntity, 0x68)

// GLOBAL: LEGO1 0x100f0c2c
// STRING: LEGO1 0x100f0c24
const char* g_chest = "chest";

// GLOBAL: LEGO1 0x100f0c30
// STRING: LEGO1 0x100f0c18
const char* g_cavedoor = "cavedoor";

// GLOBAL: LEGO1 0x100f0c34
IsleScript::Script g_nextChestAction = IsleScript::c_nca001ca_RunAnim;

// GLOBAL: LEGO1 0x100f0c38
IsleScript::Script g_nextCavedoorAction = IsleScript::c_Avo900Ps_PlayWav;

// FUNCTION: LEGO1 0x100150c0
MxLong InfoCenterEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	switch (GameState()->GetCurrentAct()) {
	case LegoGameState::Act::e_act1: {
		if (UserActor()->GetActorId() != GameState()->GetActorId()) {
			((IslePathActor*) UserActor())->Exit();
		}

		Isle* isle = (Isle*) FindWorld(*g_isleScript, IsleScript::c__Isle);
		isle->SwitchToInfocenter();
		isle->SetDestLocation(LegoGameState::Area::e_infomain);

		Act1State* act1state = (Act1State*) GameState()->GetState("Act1State");
		act1state->SetState(Act1State::e_none);
		break;
	}
	case LegoGameState::Act::e_act2: {
		LegoAct2* act2 = (LegoAct2*) FindWorld(*g_act2mainScript, Act2mainScript::c__Act2Main);
		act2->SetDestLocation(LegoGameState::e_infomain);

		LegoAct2State* act2state = (LegoAct2State*) GameState()->GetState("LegoAct2State");
		if (act2state) {
			act2state->m_enabled = FALSE;
		}
		break;
	}
	case LegoGameState::Act::e_act3:
		Act3* act3 = (Act3*) FindWorld(*g_act3Script, Act3Script::c__Act3);
		act3->SetDestLocation(LegoGameState::e_infomain);
		break;
	}

	AnimationManager()->FUN_10061010(FALSE);
	TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
	return 1;
}

// FUNCTION: LEGO1 0x100151d0
MxLong GasStationEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	if (CanExit()) {
		Act1State* state = (Act1State*) GameState()->GetState("Act1State");

		if (state->GetState() != Act1State::e_towtrack) {
			state->SetState(Act1State::e_none);

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
	if (CanExit()) {
		Act1State* act1State = (Act1State*) GameState()->GetState("Act1State");

		if (act1State->GetState() != Act1State::e_ambulance) {
			act1State->SetState(Act1State::e_none);

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
	if (CanExit()) {
		Act1State* state = (Act1State*) GameState()->GetState("Act1State");

		if (state->GetState() != Act1State::e_ambulance) {
			state->SetState(Act1State::e_none);

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
	if (CanExit()) {
		Act1State* state = (Act1State*) GameState()->GetState("Act1State");
		state->SetState(Act1State::e_none);

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
	if (CanExit()) {
		Act1State* state = (Act1State*) GameState()->GetState("Act1State");
		state->SetState(Act1State::e_none);

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

// FUNCTION: LEGO1 0x100154f0
// FUNCTION: BETA10 0x100256e8
MxLong JailEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	if (CanExit()) {
		PlayCamAnim(UserActor(), FALSE, 18, TRUE);
	}

	return 1;
}

// FUNCTION: LEGO1 0x10015520
// FUNCTION: BETA10 0x10025719
MxLong CaveEntity::HandleClick(LegoEventNotificationParam& p_param)
{
	LegoROI* roi = p_param.GetROI();

	if (!strncmp(roi->GetName(), g_chest, strlen(g_chest))) {
		DeleteObjects(g_isleScript, IsleScript::c_nca001ca_RunAnim, IsleScript::c_nca003gh_RunAnim);
		StartIsleAction(g_nextChestAction);

		switch (g_nextChestAction) {
		case IsleScript::c_nca001ca_RunAnim:
			g_nextChestAction = IsleScript::c_nca002sk_RunAnim;
			break;
		case IsleScript::c_nca002sk_RunAnim:
			g_nextChestAction = IsleScript::c_nca003gh_RunAnim;
			break;
		case IsleScript::c_nca003gh_RunAnim:
			g_nextChestAction = IsleScript::c_nca001ca_RunAnim;
			break;
		}
	}
	else if (!strcmp(roi->GetName(), g_cavedoor)) {
		DeleteObjects(g_isleScript, IsleScript::c_Avo900Ps_PlayWav, IsleScript::c_Avo904Ps_PlayWav);
		StartIsleAction(g_nextCavedoorAction);
		BackgroundAudioManager()->LowerVolume();

		switch (g_nextCavedoorAction) {
		case IsleScript::c_Avo900Ps_PlayWav:
			g_nextCavedoorAction = IsleScript::c_Avo901Ps_PlayWav;
			break;
		case IsleScript::c_Avo901Ps_PlayWav:
			g_nextCavedoorAction = IsleScript::c_Avo902Ps_PlayWav;
			break;
		case IsleScript::c_Avo902Ps_PlayWav:
			g_nextCavedoorAction = IsleScript::c_Avo903Ps_PlayWav;
			break;
		case IsleScript::c_Avo903Ps_PlayWav:
			g_nextCavedoorAction = IsleScript::c_Avo904Ps_PlayWav;
			break;
		case IsleScript::c_Avo904Ps_PlayWav:
			g_nextCavedoorAction = IsleScript::c_Avo900Ps_PlayWav;
			break;
		}
	}

	return 1;
}
