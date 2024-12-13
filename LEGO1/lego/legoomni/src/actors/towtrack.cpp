#include "towtrack.h"

#include "isle.h"
#include "isle_actions.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legonavcontroller.h"
#include "legopathstruct.h"
#include "legoutils.h"
#include "legovariables.h"
#include "legoworld.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxsoundpresenter.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"

DECOMP_SIZE_ASSERT(TowTrack, 0x180)
DECOMP_SIZE_ASSERT(TowTrackMissionState, 0x28)

// Flags used in isle.cpp
extern MxU32 g_isleFlags;

// FUNCTION: LEGO1 0x1004c720
TowTrack::TowTrack()
{
	m_unk0x168 = 0;
	m_actorId = -1;
	m_state = NULL;
	m_unk0x16c = 0;
	m_lastAction = IsleScript::c_noneIsle;
	m_unk0x16e = 0;
	m_lastAnimation = IsleScript::c_noneIsle;
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
void TowTrack::Animate(float p_time)
{
	IslePathActor::Animate(p_time);

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

		if (p_time - m_state->m_startTime > 100000.0f && m_state->m_unk0x08 == 1 && !m_state->m_unk0x10) {
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
// FUNCTION: BETA10 0x100f6de2
MxLong TowTrack::Notify(MxParam& p_param)
{
	MxLong result = 0;
	MxNotificationParam& param = (MxNotificationParam&) p_param;

	switch (param.GetNotification()) {
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

// FUNCTION: LEGO1 0x1004cd40
// FUNCTION: BETA10 0x100f6f1f
MxLong TowTrack::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	if (p_param.GetAction() != NULL) {
		IsleScript::Script objectId = (IsleScript::Script) p_param.GetAction()->GetObjectId();

		if (m_lastAnimation == objectId) {
			m_lastAnimation = IsleScript::c_noneIsle;
		}

		if (m_lastAction == objectId) {
			if (m_lastAnimation == IsleScript::c_noneIsle) {
				BackgroundAudioManager()->RaiseVolume();
			}

			m_lastAction = IsleScript::c_noneIsle;
		}
		else if (objectId == IsleScript::c_wrt060bm_RunAnim) {
			if (m_actorId < LegoActor::c_pepper || m_actorId > LegoActor::c_laura) {
				m_actorId = LegoActor::c_laura;
			}

			switch ((rand() % ((m_actorId != 4 ? 4 : 3))) + 1) {
			case 1:
				PlayFinalAnimation(IsleScript::c_wrt074sl_RunAnim);
				break;
			case 2:
				PlayFinalAnimation(IsleScript::c_wrt075rh_RunAnim);
				break;
			case 3:
				PlayFinalAnimation(IsleScript::c_wrt076df_RunAnim);
				break;
			case 4:
				PlayFinalAnimation(IsleScript::c_wrt078ni_RunAnim);
				break;
			}
		}
		else if (objectId == IsleScript::c_wrt074sl_RunAnim || objectId == IsleScript::c_wrt075rh_RunAnim || objectId == IsleScript::c_wrt076df_RunAnim || objectId == IsleScript::c_wrt078ni_RunAnim) {
			m_state->m_unk0x08 = 2;
			CurrentWorld()->PlaceActor(UserActor());
			HandleClick();
		}
		else if (objectId == IsleScript::c_wgs083nu_RunAnim) {
			if (m_actorId < LegoActor::c_pepper || m_actorId > LegoActor::c_laura) {
				m_actorId = LegoActor::c_laura;
			}

			switch (m_actorId) {
			case c_pepper:
				FUN_1004dcb0(IsleScript::c_wgs085nu_RunAnim);
				break;
			case c_mama:
				FUN_1004dcb0(IsleScript::c_wgs086nu_RunAnim);
				break;
			case c_papa:
				FUN_1004dcb0(IsleScript::c_wgs088nu_RunAnim);
				break;
			case c_nick:
				FUN_1004dcb0(IsleScript::c_wgs087nu_RunAnim);
				break;
			case c_laura:
				FUN_1004dcb0(IsleScript::c_wgs089nu_RunAnim);
				break;
			}

			m_state->UpdateScore(LegoState::e_red, m_actorId);

			AnimationManager()->FUN_1005f6d0(TRUE);
			g_isleFlags |= Isle::c_playMusic;
			AnimationManager()->EnableCamAnims(TRUE);
		}
		else if (objectId == IsleScript::c_wgs090nu_RunAnim) {
			if (m_actorId < LegoActor::c_pepper || m_actorId > LegoActor::c_laura) {
				m_actorId = LegoActor::c_laura;
			}

			switch (m_actorId) {
			case c_pepper:
				FUN_1004dcb0(IsleScript::c_wgs091nu_RunAnim);
				break;
			case c_mama:
				FUN_1004dcb0(IsleScript::c_wgs092nu_RunAnim);
				break;
			case c_papa:
				FUN_1004dcb0(IsleScript::c_wgs094nu_RunAnim);
				break;
			case c_nick:
				FUN_1004dcb0(IsleScript::c_wgs093nu_RunAnim);
				break;
			case c_laura:
				FUN_1004dcb0(IsleScript::c_wgs095nu_RunAnim);
				break;
			}

			m_state->UpdateScore(LegoState::e_blue, m_actorId);
		}
		else if (objectId == IsleScript::c_wgs097nu_RunAnim) {
			if (m_actorId < LegoActor::c_pepper || m_actorId > LegoActor::c_laura) {
				m_actorId = LegoActor::c_laura;
			}

			switch (m_actorId) {
			case c_pepper:
				FUN_1004dcb0(IsleScript::c_wgs098nu_RunAnim);
				break;
			case c_mama:
				FUN_1004dcb0(IsleScript::c_wgs099nu_RunAnim);
				break;
			case c_papa:
				FUN_1004dcb0(IsleScript::c_wgs101nu_RunAnim);
				break;
			case c_nick:
				FUN_1004dcb0(IsleScript::c_wgs100nu_RunAnim);
				break;
			case c_laura:
				FUN_1004dcb0(IsleScript::c_wgs102nu_RunAnim);
				break;
			}

			m_state->UpdateScore(LegoState::e_yellow, m_actorId);
		}
		else if (objectId == IsleScript::c_wgs098nu_RunAnim || objectId == IsleScript::c_wgs099nu_RunAnim || objectId == IsleScript::c_wgs100nu_RunAnim || objectId == IsleScript::c_wgs101nu_RunAnim || objectId == IsleScript::c_wgs102nu_RunAnim || objectId == IsleScript::c_wgs085nu_RunAnim || objectId == IsleScript::c_wgs086nu_RunAnim || objectId == IsleScript::c_wgs087nu_RunAnim || objectId == IsleScript::c_wgs088nu_RunAnim || objectId == IsleScript::c_wgs089nu_RunAnim || objectId == IsleScript::c_wgs091nu_RunAnim || objectId == IsleScript::c_wgs092nu_RunAnim || objectId == IsleScript::c_wgs093nu_RunAnim || objectId == IsleScript::c_wgs094nu_RunAnim || objectId == IsleScript::c_wgs095nu_RunAnim) {
			((Act1State*) GameState()->GetState("Act1State"))->m_unk0x018 = 0;
			AnimationManager()->FUN_1005f6d0(TRUE);
			g_isleFlags |= Isle::c_playMusic;
			AnimationManager()->EnableCamAnims(TRUE);
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x1004d330
// FUNCTION: BETA10 0x100f74c0
MxLong TowTrack::HandlePathStruct(LegoPathStructNotificationParam& p_param)
{
	MxDSAction action;

	// 0x168 corresponds to the path at the gas station
	if (p_param.GetData() == 0x168) {
		m_fuel = 1.0f;
	}

	if (UserActor() != this) {
		return 0;
	}

	if (m_state->m_unk0x08 == 2 &&
		((p_param.GetTrigger() == LegoPathStruct::c_camAnim && (p_param.GetData() == 9 || p_param.GetData() == 8)) ||
		 (p_param.GetTrigger() == LegoPathStruct::c_w && p_param.GetData() == 0x169))) {
		m_state->m_unk0x08 = 0;

		MxLong time = Timer()->GetTime() - m_state->m_startTime;
		Leave();

		if (time < 200000) {
			PlayFinalAnimation(IsleScript::c_wgs083nu_RunAnim);
		}
		else if (time < 300000) {
			PlayFinalAnimation(IsleScript::c_wgs090nu_RunAnim);
		}
		else {
			PlayFinalAnimation(IsleScript::c_wgs097nu_RunAnim);
		}
	}
	else if (m_state->m_unk0x08 == 1 && p_param.GetTrigger() == LegoPathStruct::c_camAnim && p_param.GetData() == 0x37) {
		m_state->m_unk0x08 = 3;
		StopActions();

		if (m_lastAction != IsleScript::c_noneIsle) {
			InvokeAction(Extra::e_stop, *g_isleScript, m_lastAction, NULL);
		}

		Leave();
		PlayFinalAnimation(IsleScript::c_wrt060bm_RunAnim);
	}
	else if (p_param.GetTrigger() == LegoPathStruct::c_w && m_state->m_unk0x08 == 1) {
		if (p_param.GetData() == 0x15f) {
			if (m_unk0x16c == 0) {
				m_unk0x16c = 1;
				InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_wns050p1_RunAnim, NULL);
			}
		}
		else if (p_param.GetData() == 0x160) {
			if (m_unk0x16e == 0) {
				m_unk0x16e = 1;
				InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_wns046mg_RunAnim, NULL);
			}

			if (!m_state->m_unk0x10 && m_lastAction == IsleScript::c_noneIsle) {
				if (m_actorId < LegoActor::c_pepper || m_actorId > LegoActor::c_laura) {
					m_actorId = LegoActor::c_laura;
				}

				IsleScript::Script objectId;

				switch (m_actorId) {
				case c_pepper:
					objectId = IsleScript::c_wns034na_PlayWav;
					break;
				case c_mama:
					switch ((rand() % 2) + 1) {
					case 1:
						objectId = IsleScript::c_wns037na_PlayWav;
						break;
					case 2:
						objectId = IsleScript::c_wns038na_PlayWav;
						break;
					}
					break;
				case c_papa:
					switch ((rand() % 2) + 1) {
					case 1:
						objectId = IsleScript::c_wns041na_PlayWav;
						break;
					case 2:
						objectId = IsleScript::c_wns042na_PlayWav;
						break;
					}
					break;
				case c_nick:
					switch ((rand() % 2) + 1) {
					case 1:
						objectId = IsleScript::c_wns039na_PlayWav;
						break;
					case 2:
						objectId = IsleScript::c_wns040na_PlayWav;
						break;
					}
					break;
				case c_laura:
					switch ((rand() % 2) + 1) {
					case 1:
						objectId = IsleScript::c_wns043na_PlayWav;
						break;
					case 2:
						objectId = IsleScript::c_wns044na_PlayWav;
						break;
					}
					break;
				}

				PlayAction(objectId);
			}
		}
	}

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
		m_lastAction = IsleScript::c_noneIsle;
		m_lastAnimation = IsleScript::c_noneIsle;
		m_state->m_startTime = Timer()->GetTime();
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

// FUNCTION: LEGO1 0x1004dbe0
void TowTrack::FUN_1004dbe0()
{
	if (m_lastAction != -1) {
		InvokeAction(Extra::e_stop, *g_isleScript, m_lastAction, NULL);
	}

	((Act1State*) GameState()->GetState("Act1State"))->m_unk0x018 = 0;
	m_state->m_unk0x08 = 0;
	g_isleFlags |= Isle::c_playMusic;
	AnimationManager()->EnableCamAnims(TRUE);
	AnimationManager()->FUN_1005f6d0(TRUE);
	m_state->m_startTime = INT_MIN;
	m_state->m_unk0x10 = FALSE;
	m_state = NULL;
	m_unk0x16c = 0;
	m_unk0x16e = 0;
}

// FUNCTION: LEGO1 0x1004dc80
// FUNCTION: BETA10 0x100f86a0
void TowTrack::PlayFinalAnimation(IsleScript::Script p_objectId)
{
	AnimationManager()->FUN_10060dc0(p_objectId, NULL, TRUE, FALSE, NULL, FALSE, FALSE, FALSE, TRUE);
	m_lastAnimation = p_objectId;
}

// FUNCTION: LEGO1 0x1004dcb0
void TowTrack::FUN_1004dcb0(IsleScript::Script p_objectId)
{
	AnimationManager()->FUN_1005f6d0(TRUE);
	AnimationManager()->FUN_10060dc0(p_objectId, NULL, TRUE, TRUE, NULL, FALSE, TRUE, TRUE, TRUE);
	m_lastAnimation = p_objectId;
}

// FUNCTION: LEGO1 0x1004dcf0
void TowTrack::PlayAction(IsleScript::Script p_objectId)
{
	if (p_objectId != IsleScript::c_noneIsle) {
		InvokeAction(Extra::e_start, *g_isleScript, p_objectId, NULL);
	}

	m_lastAction = p_objectId;
	BackgroundAudioManager()->LowerVolume();
}

// FUNCTION: LEGO1 0x1004dd30
TowTrackMissionState::TowTrackMissionState()
{
	m_unk0x08 = 0;
	m_startTime = 0;
	m_unk0x10 = FALSE;
	m_peScore = 0;
	m_maScore = 0;
	m_paScore = 0;
	m_niScore = 0;
	m_laScore = 0;
	m_peHighScore = 0;
	m_maHighScore = 0;
	m_paHighScore = 0;
	m_niHighScore = 0;
	m_laHighScore = 0;
}

// FUNCTION: LEGO1 0x1004dde0
MxResult TowTrackMissionState::Serialize(LegoFile* p_file)
{
	LegoState::Serialize(p_file);

	if (p_file->IsReadMode()) {
		Read(p_file, &m_peScore);
		Read(p_file, &m_maScore);
		Read(p_file, &m_paScore);
		Read(p_file, &m_niScore);
		Read(p_file, &m_laScore);
		Read(p_file, &m_peHighScore);
		Read(p_file, &m_maHighScore);
		Read(p_file, &m_paHighScore);
		Read(p_file, &m_niHighScore);
		Read(p_file, &m_laHighScore);
	}
	else if (p_file->IsWriteMode()) {
		Write(p_file, m_peScore);
		Write(p_file, m_maScore);
		Write(p_file, m_paScore);
		Write(p_file, m_niScore);
		Write(p_file, m_laScore);
		Write(p_file, m_peHighScore);
		Write(p_file, m_maHighScore);
		Write(p_file, m_paHighScore);
		Write(p_file, m_niHighScore);
		Write(p_file, m_laHighScore);
	}

	return SUCCESS;
}
