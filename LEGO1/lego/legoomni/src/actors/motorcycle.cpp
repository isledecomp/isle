#include "motorcycle.h"

#include "isle.h"
#include "isle_actions.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legocontrolmanager.h"
#include "legonavcontroller.h"
#include "legopathstruct.h"
#include "legoutils.h"
#include "legovariables.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"

DECOMP_SIZE_ASSERT(Motocycle, 0x16c)

// FUNCTION: LEGO1 0x100357b0
Motocycle::Motocycle()
{
	m_maxLinearVel = 40.0;
	m_unk0x150 = 1.75;
	m_unk0x148 = 1;
	m_fuel = 1.0;
}

// FUNCTION: LEGO1 0x10035a40
MxResult Motocycle::Create(MxDSAction& p_dsAction)
{
	MxResult result = IslePathActor::Create(p_dsAction);
	m_world = CurrentWorld();

	if (m_world) {
		m_world->Add(this);
	}

	VariableTable()->SetVariable(g_varMOTOFUEL, "1.0");
	m_fuel = 1.0;
	m_time = Timer()->GetTime();
	return result;
}

// FUNCTION: LEGO1 0x10035ad0
void Motocycle::Animate(float p_time)
{
	IslePathActor::Animate(p_time);

	if (UserActor() == this) {
		char buf[200];
		float speed = abs(m_worldSpeed);
		float maxLinearVel = NavController()->GetMaxLinearVel();

		sprintf(buf, "%g", speed / maxLinearVel);
		VariableTable()->SetVariable(g_varMOTOSPEED, buf);

		m_fuel += (p_time - m_time) * -3.333333333e-06f;
		if (m_fuel < 0) {
			m_fuel = 0;
		}

		m_time = p_time;

		sprintf(buf, "%g", m_fuel);
		VariableTable()->SetVariable(g_varMOTOFUEL, buf);
	}
}

// FUNCTION: LEGO1 0x10035bc0
void Motocycle::Exit()
{
	IslePathActor::Exit();
	GameState()->m_currentArea = LegoGameState::e_motocycle;
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_MotoBikeDashboard_Bitmap);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_MotoBikeArms_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_MotoBikeInfo_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_MotoBikeSpeedMeter);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_MotoBikeFuelMeter);
	ControlManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10035c50
MxLong Motocycle::HandleClick()
{
	if (!FUN_1003ef60()) {
		return 1;
	}

	FUN_10015820(TRUE, 0);

	((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::Area::e_motocycle);
	TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, TRUE);

	if (GameState()->GetActorId() != UserActor()->GetActorId()) {
		((IslePathActor*) UserActor())->Exit();
	}

	m_time = Timer()->GetTime();

	Enter();
	InvokeAction(Extra::ActionType::e_start, *g_isleScript, IsleScript::c_MotoBikeDashboard, NULL);
	GetCurrentAction().SetObjectId(-1);

	Vector3 position = m_roi->GetWorldPosition();
	AnimationManager()->FUN_10064670(&position);
	AnimationManager()->FUN_10064740(&position);
	ControlManager()->Register(this);
	return 1;
}

// FUNCTION: LEGO1 0x10035d70
MxLong Motocycle::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	MxLong result = 0;

	if (p_param.GetUnknown0x28() == 1) {
		switch (p_param.GetClickedObjectId()) {
		case IsleScript::c_MotoBikeArms_Ctl:
			Exit();
			GameState()->m_currentArea = LegoGameState::e_unk66;
			result = 1;
			break;
		case IsleScript::c_MotoBikeInfo_Ctl:
			((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::e_infomain);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			Exit();
			result = 1;
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10035df0
MxLong Motocycle::HandlePathStruct(LegoPathStructNotificationParam& p_param)
{
	// 0x168 corresponds to the path at the gas station
	if (p_param.GetData() == 0x168) {
		m_fuel = 1.0f;
	}

	return 0;
}

// FUNCTION: LEGO1 0x10035e10
void Motocycle::ActivateSceneActions()
{
	PlayMusic(JukeboxScript::c_PoliceStation_Music);

	Act1State* act1state = (Act1State*) GameState()->GetState("Act1State");
	if (!act1state->m_unk0x022) {
		act1state->m_unk0x022 = TRUE;

		MxMatrix mat(UserActor()->GetROI()->GetLocal2World());
		mat.TranslateBy(mat[2][0] * 2.5, mat[2][1] + 0.7, mat[2][2] * 2.5);

		AnimationManager()
			->FUN_10060dc0(IsleScript::c_sns006in_RunAnim, &mat, TRUE, FALSE, NULL, FALSE, TRUE, TRUE, TRUE);
	}
}
