#include "jetski.h"

#include "dunebuggy.h"
#include "isle.h"
#include "isle_actions.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legocontrolmanager.h"
#include "legonavcontroller.h"
#include "legoutils.h"
#include "legovariables.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(Jetski, 0x164)

// These two have been changed between BETA10 and LEGO1
// GLOBAL: LEGO1 0x100f7ab8
// STRING: LEGO1 0x100f3ce0
// GLOBAL: BETA10 0x101e0be4
const char* g_varJSFRNTY5 = "c_jsfrnty5";

// GLOBAL: LEGO1 0x100f7abc
// STRING: LEGO1 0x100f3ca4
// GLOBAL: BETA10 0x101e0be0
const char* g_varJSWNSHY5 = "c_jswnshy5";

// FUNCTION: LEGO1 0x1007e3b0
Jetski::Jetski()
{
	m_maxLinearVel = 25.0;
	m_unk0x150 = 2.0;
	m_unk0x148 = 1;
}

// FUNCTION: LEGO1 0x1007e630
MxResult Jetski::Create(MxDSAction& p_dsAction)
{
	MxResult result = IslePathActor::Create(p_dsAction);
	m_world = CurrentWorld();

	if (m_world) {
		m_world->Add(this);
	}

	VariableTable()->SetVariable(g_varJETFUEL, "0.8");
	return result;
}

// FUNCTION: LEGO1 0x1007e680
void Jetski::Animate(float p_time)
{
	IslePathActor::Animate(p_time);

	char buf[200];
	float speed = abs(m_worldSpeed);
	float maxLinearVel = NavController()->GetMaxLinearVel();

	sprintf(buf, "%g", speed / maxLinearVel);
	VariableTable()->SetVariable(g_varJETSPEED, buf);
}

// FUNCTION: LEGO1 0x1007e6f0
void Jetski::Exit()
{
	SpawnPlayer(LegoGameState::e_unk45, FALSE, c_spawnBit1 | c_playMusic | c_spawnBit3);
	IslePathActor::Exit();
	GameState()->m_currentArea = LegoGameState::e_jetski;
	RemoveFromWorld();
	EnableAnimations(TRUE);
	SetIsWorldActive(TRUE);
	ControlManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x1007e750
// FUNCTION: BETA10 0x10037621
MxLong Jetski::HandleClick()
{
#ifndef BETA10
	if (!CanExit()) {
		return 1;
	}

	Disable(TRUE, 0);

	((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::Area::e_jetski);
	TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, TRUE);

	if (GameState()->GetActorId() != UserActor()->GetActorId()) {
		((IslePathActor*) UserActor())->Exit();
	}
#endif

	// Selects the windshield from `IsleScript::c_JetskiDashboard11_Bitmap` (=41)
	// to `IsleScript::c_JetskiDashboard66_Bitmap` based on the user's color selection
	MxS32 colorOffset = DuneBuggy::GetColorOffset(g_varJSWNSHY5);
	m_jetskiDashboardStreamId = 10 * (colorOffset + 3);
	colorOffset = DuneBuggy::GetColorOffset(g_varJSFRNTY5);
	m_jetskiDashboardStreamId += colorOffset;

	InvokeAction(Extra::ActionType::e_start, *g_isleScript, m_jetskiDashboardStreamId, NULL);
	InvokeAction(Extra::ActionType::e_start, *g_isleScript, IsleScript::c_JetskiDashboard, NULL);

#ifdef BETA10
	if (UserActor()->GetActorId() != GameState()->GetActorId()) {
		((IslePathActor*) UserActor())->Exit();
	}
	Enter();
	ControlManager()->Register(this);
	PlayCamAnim(this, FALSE, 0x44, TRUE);
#else
	GetCurrentAction().SetObjectId(-1);

	AnimationManager()->FUN_1005f6d0(FALSE);
	AnimationManager()->FUN_10064670(NULL);
	Enter();
	ControlManager()->Register(this);
#endif

	return 1;
}

// FUNCTION: LEGO1 0x1007e880
void Jetski::RemoveFromWorld()
{
	RemoveFromCurrentWorld(*g_isleScript, m_jetskiDashboardStreamId);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_JetskiArms_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_JetskiInfo_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_JetskiSpeedMeter);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_JetskiFuelMeter);
}

// FUNCTION: LEGO1 0x1007e8e0
MxLong Jetski::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	if (p_param.m_enabledChild == 1 && CurrentWorld()->IsA("Isle")) {
		switch (p_param.m_clickedObjectId) {
		case IsleScript::c_JetskiArms_Ctl:
			Exit();
			((IslePathActor*) UserActor())
				->SpawnPlayer(LegoGameState::e_jetraceExterior, TRUE, c_spawnBit1 | c_playMusic | c_spawnBit3);
			GameState()->m_currentArea = LegoGameState::e_vehicleExited;
			return 1;
		case IsleScript::c_JetskiInfo_Ctl:
			((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::e_infomain);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			Exit();
			return 1;
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x1007e990
void Jetski::ActivateSceneActions()
{
	PlayMusic(JukeboxScript::c_JetskiRace_Music);

	Act1State* act1state = (Act1State*) GameState()->GetState("Act1State");
	if (!act1state->m_state) {
		if (act1state->m_unk0x022) {
			PlayCamAnim(this, FALSE, 68, TRUE);
		}
		else {
			act1state->m_unk0x022 = TRUE;

			LegoPathActor* user = UserActor();
			if (user != NULL) {
				MxMatrix mat(user->GetROI()->GetLocal2World());
				mat.TranslateBy(mat[2][0] * 2.5, mat[2][1] + 0.6, mat[2][2] * 2.5);

				AnimationManager()->FUN_10060dc0(
					IsleScript::c_sjs007in_RunAnim,
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
	}
}
