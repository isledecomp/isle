#include "dunebuggy.h"

#include "decomp.h"
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
#include "mxsoundpresenter.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"

DECOMP_SIZE_ASSERT(DuneBuggy, 0x16c)

// GLOBAL: LEGO1 0x100f7660
// STRING: LEGO1 0x100f7634
const char* g_varDBFRFNY4 = "C_DBFRFNY4";

// FUNCTION: LEGO1 0x10067bb0
DuneBuggy::DuneBuggy()
{
	m_maxLinearVel = 25.0;
	m_fuel = 1.0;
}

// FUNCTION: LEGO1 0x10067e30
MxResult DuneBuggy::Create(MxDSAction& p_dsAction)
{
	MxResult result = IslePathActor::Create(p_dsAction);
	m_world = CurrentWorld();

	if (m_world) {
		m_world->Add(this);
	}

	VariableTable()->SetVariable(g_varDUNEFUEL, "1.0");
	m_fuel = 1.0;
	m_time = Timer()->GetTime();
	return result;
}

// FUNCTION: LEGO1 0x10067ec0
void DuneBuggy::Animate(float p_time)
{
	IslePathActor::Animate(p_time);

	char buf[200];
	float speed = abs(m_worldSpeed);
	float maxLinearVel = NavController()->GetMaxLinearVel();

	sprintf(buf, "%g", speed / maxLinearVel);
	VariableTable()->SetVariable(g_varDUNESPEED, buf);

	m_fuel += (p_time - m_time) * -3.333333333e-06f;
	if (m_fuel < 0) {
		m_fuel = 0;
	}

	m_time = p_time;

	sprintf(buf, "%g", m_fuel);
	VariableTable()->SetVariable(g_varDUNEFUEL, buf);
}

// FUNCTION: LEGO1 0x10067fa0
void DuneBuggy::Exit()
{
	IslePathActor::Exit();
	GameState()->m_currentArea = LegoGameState::e_dunecar;
	RemoveFromCurrentWorld(*g_isleScript, m_dashboard);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_DuneCarArms_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_DuneCarHorn_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_DuneCarHorn_Sound);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_DuneCarInfo_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_DuneCarSpeedMeter);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_DuneCarFuelMeter);
	ControlManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10068060
MxLong DuneBuggy::HandleClick()
{
	if (!FUN_1003ef60()) {
		return 1;
	}

	FUN_10015820(TRUE, 0);

	((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::Area::e_dunecar);
	TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, TRUE);

	if (GameState()->GetActorId() != UserActor()->GetActorId()) {
		((IslePathActor*) UserActor())->Exit();
	}

	m_time = Timer()->GetTime();
	m_dashboard = IsleScript::c_DuneCarSpeedMeter + GetColorOffset(g_varDBFRFNY4);

	InvokeAction(Extra::ActionType::e_start, *g_isleScript, m_dashboard, NULL);
	InvokeAction(Extra::ActionType::e_start, *g_isleScript, IsleScript::c_DuneCarDashboard, NULL);
	GetCurrentAction().SetObjectId(-1);

	Vector3 position = m_roi->GetWorldPosition();
	AnimationManager()->FUN_10064670(&position);
	AnimationManager()->FUN_10064740(&position);
	Enter();
	ControlManager()->Register(this);
	return 1;
}

// FUNCTION: LEGO1 0x100681b0
MxLong DuneBuggy::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	MxLong result = 0;

	if (p_param.GetUnknown0x28() == 1) {
		switch (p_param.GetClickedObjectId()) {
		case IsleScript::c_DuneCarArms_Ctl:
			Exit();
			GameState()->m_currentArea = LegoGameState::e_unk66;
			result = 1;
			break;
		case IsleScript::c_DuneCarInfo_Ctl:
			((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::e_infomain);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			Exit();
			result = 1;
			break;
		case IsleScript::c_DuneCarHorn_Ctl:
			MxSoundPresenter* presenter =
				(MxSoundPresenter*) CurrentWorld()->Find("MxSoundPresenter", "DuneCarHorn_Sound");
			presenter->Enable(p_param.GetUnknown0x28());
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10068270
MxLong DuneBuggy::HandlePathStruct(LegoPathStructNotificationParam& p_param)
{
	// 0x168 corresponds to the path at the gas station
	if (p_param.GetData() == 0x168) {
		m_fuel = 1.0f;
	}

	return 0;
}

// FUNCTION: LEGO1 0x10068290
MxS32 DuneBuggy::GetColorOffset(const char* p_variable)
{
	MxS32 offset = 1;
	const char* colorName = VariableTable()->GetVariable(p_variable);

	if (strcmpi(colorName, "lego green")) {
		if (!strcmpi(colorName, "lego red")) {
			offset = 2;
		}
		else if (!strcmpi(colorName, "lego yellow")) {
			offset = 3;
		}
		else if (!strcmpi(colorName, "lego black")) {
			offset = 4;
		}
		else if (!strcmpi(colorName, "lego blue")) {
			offset = 5;
		}
		else if (!strcmpi(colorName, "lego white")) {
			offset = 6;
		}
	}

	return offset;
}

// FUNCTION: LEGO1 0x10068350
void DuneBuggy::ActivateSceneActions()
{
	PlayMusic(JukeboxScript::c_GarageArea_Music);

	Act1State* act1state = (Act1State*) GameState()->GetState("Act1State");
	if (!act1state->m_unk0x022) {
		act1state->m_unk0x022 = TRUE;

		MxMatrix mat(UserActor()->GetROI()->GetLocal2World());
		mat.TranslateBy(mat[2][0] * 2.5, mat[2][1] + 0.7, mat[2][2] * 2.5);

		AnimationManager()->FUN_10060dc0(
			IsleScript::c_sns005in_RunAnim,
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
