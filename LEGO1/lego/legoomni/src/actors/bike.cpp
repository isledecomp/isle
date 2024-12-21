#include "bike.h"

#include "isle.h"
#include "isle_actions.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoutils.h"
#include "legoworld.h"
#include "misc.h"
#include "mxsoundpresenter.h"
#include "mxtransitionmanager.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(Bike, 0x164)

// FUNCTION: LEGO1 0x10076670
Bike::Bike()
{
	m_maxLinearVel = 20.0;
	m_unk0x150 = 3.0;
	m_unk0x148 = 1;
}

// FUNCTION: LEGO1 0x100768f0
MxResult Bike::Create(MxDSAction& p_dsAction)
{
	MxResult result = IslePathActor::Create(p_dsAction);
	m_world = CurrentWorld();

	if (m_world) {
		m_world->Add(this);
	}

	return result;
}

// FUNCTION: LEGO1 0x10076920
void Bike::Exit()
{
	IslePathActor::Exit();
	GameState()->m_currentArea = LegoGameState::Area::e_bike;
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_BikeDashboard_Bitmap);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_BikeArms_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_BikeHorn_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_BikeHorn_Sound);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_BikeInfo_Ctl);
	ControlManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x100769a0
MxLong Bike::HandleClick()
{
	if (FUN_1003ef60()) {
		Act1State* state = (Act1State*) GameState()->GetState("Act1State");
		FUN_10015820(TRUE, 0);

		((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::Area::e_bike);
		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, TRUE);

		if (GameState()->GetActorId() != UserActor()->GetActorId()) {
			((IslePathActor*) UserActor())->Exit();
		}

		Enter();
		InvokeAction(Extra::ActionType::e_start, *g_isleScript, IsleScript::c_BikeDashboard, NULL);
		GetCurrentAction().SetObjectId(-1);

		Vector3 position = m_roi->GetWorldPosition();
		AnimationManager()->FUN_10064670(&position);
		AnimationManager()->FUN_10064740(&position);
		ControlManager()->Register(this);
	}

	return 1;
}

// FUNCTION: LEGO1 0x10076aa0
MxLong Bike::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	MxLong result = 0;

	if (p_param.GetUnknown0x28() == 1) {
		switch (p_param.GetClickedObjectId()) {
		case IsleScript::c_BikeArms_Ctl:
			Exit();
			GameState()->m_currentArea = LegoGameState::e_unk66;
			result = 1;
			break;
		case IsleScript::c_BikeInfo_Ctl:
			((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::e_infomain);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			Exit();
			result = 1;
			break;
		case IsleScript::c_BikeHorn_Ctl:
			MxSoundPresenter* presenter =
				(MxSoundPresenter*) CurrentWorld()->Find("MxSoundPresenter", "BikeHorn_Sound");
			presenter->Enable(p_param.GetUnknown0x28());
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10076b60
void Bike::ActivateSceneActions()
{
	PlayMusic(JukeboxScript::c_InformationCenter_Music);

	Act1State* act1state = (Act1State*) GameState()->GetState("Act1State");
	if (!act1state->m_unk0x022) {
		act1state->m_unk0x022 = TRUE;

		MxMatrix mat(UserActor()->GetROI()->GetLocal2World());
		mat.TranslateBy(mat[2][0] * 2.5, mat[2][1] + 0.7, mat[2][2] * 2.5);

		AnimationManager()->FUN_10060dc0(
			IsleScript::c_sns006in_RunAnim,
			&mat,
			TRUE,
			LegoAnimationManager::e_unk0,
			NULL,
			FALSE,
			TRUE,
			TRUE,
			TRUE
		);
	}
}
