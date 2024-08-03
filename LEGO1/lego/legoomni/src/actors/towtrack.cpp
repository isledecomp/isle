#include "towtrack.h"

#include "isle.h"
#include "isle_actions.h"
#include "jukebox_actions.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legonavcontroller.h"
#include "legoutils.h"
#include "legovariables.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxsoundpresenter.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"

DECOMP_SIZE_ASSERT(TowTrack, 0x180)
DECOMP_SIZE_ASSERT(TowTrackMissionState, 0x28)

// FUNCTION: LEGO1 0x1004c720
TowTrack::TowTrack()
{
	m_unk0x168 = 0;
	m_actorId = -1;
	m_state = NULL;
	m_unk0x16c = 0;
	m_unk0x170 = -1;
	m_unk0x16e = 0;
	m_unk0x174 = -1;
	m_maxLinearVel = 40.0;
	m_fuel = 1.0;
}

// FUNCTION: LEGO1 0x1004c970
TowTrack::~TowTrack()
{
	ControlManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x1004c9e0
// FUNCTION: BETA10 0x100f6bf1
MxResult TowTrack::Create(MxDSAction& p_dsAction)
{
	MxResult result = IslePathActor::Create(p_dsAction);

	if (result == SUCCESS) {
		m_world = CurrentWorld();

		if (m_world) {
			m_world->Add(this);
		}

		m_state = (TowTrackMissionState*) GameState()->GetState("TowTrackMissionState");
		if (!m_state) {
			m_state = new TowTrackMissionState();
			m_state->m_unk0x08 = 0;
			GameState()->RegisterState(m_state);
		}
	}

	VariableTable()->SetVariable(g_varTOWFUEL, "1.0");
	m_fuel = 1.0;
	m_time = Timer()->GetTime();
	return result;
}

// FUNCTION: LEGO1 0x1004cb10
void TowTrack::VTable0x70(float p_time)
{
	IslePathActor::VTable0x70(p_time);

	if (UserActor() == this) {
		char buf[200];
		float speed = abs(m_worldSpeed);
		float maxLinearVel = NavController()->GetMaxLinearVel();

		sprintf(buf, "%g", speed / maxLinearVel);
		VariableTable()->SetVariable(g_varTOWSPEED, buf);

		m_fuel += (p_time - m_time) * -3.333333333e-06f;
		if (m_fuel < 0) {
			m_fuel = 0;
		}

		m_time = p_time;

		sprintf(buf, "%g", m_fuel);
		VariableTable()->SetVariable(g_varTOWFUEL, buf);

		if (p_time - m_state->m_unk0x0c > 100000.0f && m_state->m_unk0x08 == 1 && !m_state->m_unk0x10) {
			PlayAction(IsleScript::c_Avo909In_PlayWav);
			m_state->m_unk0x10 = TRUE;
		}
	}
}

// FUNCTION: LEGO1 0x1004cc40
void TowTrack::CreateState()
{
	m_state = (TowTrackMissionState*) GameState()->GetState("TowTrackMissionState");
	if (m_state == NULL) {
		m_state = (TowTrackMissionState*) GameState()->CreateState("TowTrackMissionState");
	}
}

// FUNCTION: LEGO1 0x1004cc80
MxLong TowTrack::Notify(MxParam& p_param)
{
	MxLong result = 0;

	switch (((MxNotificationParam&) p_param).GetNotification()) {
	case c_notificationType0:
		result = HandleNotification0();
		break;
	case c_notificationEndAction:
		result = HandleEndAction((MxEndActionNotificationParam&) p_param);
		break;
	case c_notificationClick:
		result = HandleClick();
		break;
	case c_notificationControl:
		result = HandleControl((LegoControlManagerNotificationParam&) p_param);
		break;
	case c_notificationEndAnim:
		result = HandleEndAnim((LegoEndAnimNotificationParam&) p_param);
		break;
	case c_notificationPathStruct:
		result = HandlePathStruct((LegoPathStructNotificationParam&) p_param);
		break;
	}

	return result;
}

// FUNCTION: LEGO1 0x1004cd30
MxLong TowTrack::HandleEndAnim(LegoEndAnimNotificationParam& p_param)
{
	return 1;
}

// STUB: LEGO1 0x1004cd40
MxLong TowTrack::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1004d330
MxLong TowTrack::HandlePathStruct(LegoPathStructNotificationParam& p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x1004d690
MxLong TowTrack::HandleClick()
{
	if (((Act1State*) GameState()->GetState("Act1State"))->m_unk0x018 != 8) {
		return 1;
	}

	if (m_state->m_unk0x08 == 3) {
		return 1;
	}

	FUN_10015820(TRUE, 0);
	((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::e_towtrack);
	TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);

	if (UserActor()->GetActorId() != GameState()->GetActorId()) {
		((IslePathActor*) UserActor())->Exit();
	}

	m_time = Timer()->GetTime();
	m_actorId = UserActor()->GetActorId();

	Enter();
	InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_TowTrackDashboard, NULL);
	ControlManager()->Register(this);

	if (m_state->m_unk0x08 == 0) {
		return 1;
	}

	if (m_state->m_unk0x08 == 2) {
		SpawnPlayer(LegoGameState::e_unk52, TRUE, 0);
		FindROI("rcred")->SetVisibility(FALSE);
	}
	else {
		SpawnPlayer(LegoGameState::e_unk28, TRUE, 0);
		m_unk0x170 = -1;
		m_unk0x174 = -1;
		m_state->m_unk0x0c = Timer()->GetTime();
		m_state->m_unk0x10 = FALSE;
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_wns057rd_RunAnim, NULL);
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_wns048p1_RunAnim, NULL);
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_wns049p1_RunAnim, NULL);
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_wns051bd_RunAnim, NULL);
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_wns053pr_RunAnim, NULL);
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_wns045di_RunAnim, NULL);
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_pns123pr_RunAnim, NULL);
	}

	return 1;
}

// FUNCTION: LEGO1 0x1004d8f0
void TowTrack::Exit()
{
	GameState()->m_currentArea = LegoGameState::e_garageExterior;
	StopActions();
	FUN_1004dbe0();
	Leave();
}

// FUNCTION: LEGO1 0x1004d920
void TowTrack::Leave()
{
	IslePathActor::Exit();
	CurrentWorld()->RemoveActor(this);
	m_roi->SetVisibility(FALSE);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_TowTrackDashboard_Bitmap);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_TowTrackArms_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_TowHorn_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_TowHorn_Sound);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_TowInfo_Ctl);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_TowSpeedMeter);
	RemoveFromCurrentWorld(*g_isleScript, IsleScript::c_TowFuelMeter);
	ControlManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x1004d9e0
MxLong TowTrack::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	MxLong result = 0;

	if (p_param.GetUnknown0x28() == 1) {
		switch (p_param.GetClickedObjectId()) {
		case IsleScript::c_TowTrackArms_Ctl:
			Exit();
			GameState()->m_currentArea = LegoGameState::e_unk66;
			result = 1;
			break;
		case IsleScript::c_TowInfo_Ctl:
			((Isle*) CurrentWorld())->SetDestLocation(LegoGameState::e_infomain);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			Exit();
			GameState()->m_currentArea = LegoGameState::e_unk66;
			result = 1;
			break;
		case IsleScript::c_TowHorn_Ctl:
			MxSoundPresenter* presenter = (MxSoundPresenter*) CurrentWorld()->Find("MxSoundPresenter", "TowHorn_Sound");
			presenter->Enable(p_param.GetUnknown0x28());
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1004dab0
void TowTrack::FUN_1004dab0()
{
	m_state->m_unk0x08 = 1;
	HandleClick();
}

// FUNCTION: LEGO1 0x1004dad0
void TowTrack::ActivateSceneActions()
{
	PlayMusic(JukeboxScript::c_JBMusic2);

	if (m_state->m_unk0x08 != 0) {
		if (m_state->m_unk0x08 == 2) {
			PlayAction(IsleScript::c_wrt082na_PlayWav);
		}
		else {
			PlayAction(IsleScript::c_wgs032nu_PlayWav);
		}
	}
}

// FUNCTION: LEGO1 0x1004db10
void TowTrack::StopActions()
{
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_wns050p1_RunAnim, NULL);
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_wns046mg_RunAnim, NULL);
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_wns057rd_RunAnim, NULL);
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_wns048p1_RunAnim, NULL);
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_wns049p1_RunAnim, NULL);
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_wns051bd_RunAnim, NULL);
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_wns053pr_RunAnim, NULL);
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_wns045di_RunAnim, NULL);
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_pns123pr_RunAnim, NULL);
}

// STUB: LEGO1 0x1004dbe0
void TowTrack::FUN_1004dbe0()
{
	// TODO
}

// STUB: LEGO1 0x1004dcf0
void TowTrack::PlayAction(IsleScript::Script)
{
	// TODO
}

// FUNCTION: LEGO1 0x1004dd30
TowTrackMissionState::TowTrackMissionState()
{
	m_unk0x12 = 0;
	m_unk0x14 = 0;
	m_unk0x16 = 0;
	m_unk0x08 = 0;
	m_unk0x18 = 0;
	m_unk0x0c = 0;
	m_unk0x1a = 0;
	m_unk0x10 = FALSE;
	m_score1 = 0;
	m_score2 = 0;
	m_score3 = 0;
	m_score4 = 0;
	m_score5 = 0;
}

// FUNCTION: LEGO1 0x1004dde0
MxResult TowTrackMissionState::Serialize(LegoFile* p_file)
{
	LegoState::Serialize(p_file);

	if (p_file->IsReadMode()) {
		Read(p_file, &m_unk0x12);
		Read(p_file, &m_unk0x14);
		Read(p_file, &m_unk0x16);
		Read(p_file, &m_unk0x18);
		Read(p_file, &m_unk0x1a);
		Read(p_file, &m_score1);
		Read(p_file, &m_score2);
		Read(p_file, &m_score3);
		Read(p_file, &m_score4);
		Read(p_file, &m_score5);
	}
	else if (p_file->IsWriteMode()) {
		Write(p_file, m_unk0x12);
		Write(p_file, m_unk0x14);
		Write(p_file, m_unk0x16);
		Write(p_file, m_unk0x18);
		Write(p_file, m_unk0x1a);
		Write(p_file, m_score1);
		Write(p_file, m_score2);
		Write(p_file, m_score3);
		Write(p_file, m_score4);
		Write(p_file, m_score5);
	}

	return SUCCESS;
}
