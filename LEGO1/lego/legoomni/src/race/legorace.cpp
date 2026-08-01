#include "legorace.h"

#include "carrace.h"
#include "carrace_actions.h"
#include "dunebuggy.h"
#include "isle.h"
#include "jetrace_actions.h"
#include "jetski_actions.h"
#include "jetskirace.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legoanimpresenter.h"
#include "legocontrolmanager.h"
#include "legomain.h"
#include "legonavcontroller.h"
#include "legopathstruct.h"
#include "legoracers.h"
#include "legoracespecial.h"
#include "legoutils.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstillpresenter.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(LegoRace, 0x144)

DECOMP_SIZE_ASSERT(RaceState::Entry, 0x06)

DECOMP_SIZE_ASSERT(RaceState, 0x2c)

DECOMP_SIZE_ASSERT(JetskiRace, 0x144)

DECOMP_SIZE_ASSERT(CarRace, 0x154)

// Defined in legopathstruct.cpp
extern MxBool g_triggerHandlingIgnoreDirection;

// Defined in jetski.cpp
extern const char* g_varJSFRNTY5;

extern const char* g_varJSWNSHY5;

// Defined in legopathactor.cpp
extern const char* g_strHIT_WALL_SOUND;

// GLOBAL: LEGO1 0x100f0c68
// STRING: LEGO1 0x100f0c5c
// GLOBAL: BETA10 0x101f5b04
// STRING: BETA10 0x101f5b14
const char* g_raceState = "RACE_STATE";

// GLOBAL: LEGO1 0x100f0c6c
// STRING: LEGO1 0x100f0c54
// GLOBAL: BETA10 0x101f5b08
// STRING: BETA10 0x101f5b20
const char* g_racing = "RACING";

// GLOBAL: LEGO1 0x100d5d10
const MxS32 CarRace::g_introAnimations[] = {
	CarraceScript::c_srt001sl_RunAnim,
	CarraceScript::c_srt002sl_RunAnim,
	CarraceScript::c_srt003sl_RunAnim,
	CarraceScript::c_srt004sl_RunAnim,
	CarraceScript::c_srt005sl_RunAnim,
	CarraceScript::c_srt001rh_RunAnim,
	CarraceScript::c_srt002rh_RunAnim,
	CarraceScript::c_srt003rh_RunAnim
};

// GLOBAL: LEGO1 0x100d5d30
const MxS32 CarRace::g_studsWinsAnimations[] = {
	CarraceScript::c_srt011sl_RunAnim,
	CarraceScript::c_srt012sl_RunAnim,
	CarraceScript::c_srt013sl_RunAnim,
	CarraceScript::c_srt014sl_RunAnim
};

// GLOBAL: LEGO1 0x100d5d40
const MxS32 CarRace::g_studsLoosesAnimation[] =
	{CarraceScript::c_srt015sl_RunAnim, CarraceScript::c_srt016sl_RunAnim, CarraceScript::c_srt017sl_RunAnim};

// GLOBAL: LEGO1 0x100d5d50
const MxS32 CarRace::g_rhodaWinsAnimations[] =
	{CarraceScript::c_srt007rh_RunAnim, CarraceScript::c_srt008rh_RunAnim, CarraceScript::c_srt009rh_RunAnim};

// GLOBAL: LEGO1 0x100d5d60
const MxS32 CarRace::g_rhodaLoosesAnimation[] =
	{CarraceScript::c_srt010rh_RunAnim, CarraceScript::c_srt011rh_RunAnim, CarraceScript::c_srt012rh_RunAnim};

// GLOBAL: LEGO1 0x100f0c70
// STRING: LEGO1 0x100f0c48
const LegoChar* g_strCRCFRNTY6 = "C_RCFRNTY6";

// GLOBAL: LEGO1 0x100f0c74
// STRING: LEGO1 0x100f0c3c
const LegoChar* g_strCRCEDGEY0 = "C_RCEDGEY0";

// GLOBAL: LEGO1 0x100f0c78
MxS32 g_lapsCount = 2;

// GLOBAL: LEGO1 0x100f0c7c
MxS32 JetskiRace::g_lapsCount = 2;

// FUNCTION: LEGO1 0x10015aa0
LegoRace::LegoRace()
{
	m_playerLaps = 0;
	m_opponent1Laps = 0;
	m_opponent2Laps = 0;
	m_playerLastPathStruct = 0;
	m_opponent1LastPathStruct = 0;
	m_opponent2LastPathStruct = 0;
	m_raceState = NULL;
	m_mapsLocators[0] = NULL;
	m_mapsLocators[1] = NULL;
	m_mapsLocators[2] = NULL;
	m_opponent1Locator = 0;
	m_opponent2Locator = 0;
	m_pathActor = 0;
	m_act1State = NULL;
	m_destLocation = LegoGameState::e_undefined;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10015ce0
// FUNCTION: BETA10 0x100c7a71
MxResult LegoRace::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);

	if (result == SUCCESS) {
		m_act1State = (Act1State*) GameState()->GetState("Act1State");
		ControlManager()->Register(this);
		m_pathActor = UserActor();
		m_pathActor->SetWorldSpeed(0);
		SetUserActor(NULL);
	}

	return result;
}

// FUNCTION: LEGO1 0x10015d40
// FUNCTION: BETA10 0x100c7ab5
LegoRace::~LegoRace()
{
	g_triggerHandlingIgnoreDirection = FALSE;
	if (m_pathActor) {
		SetUserActor(m_pathActor);
		NavController()->ResetMaxLinearVel(m_pathActor->GetMaxLinearVel());
		m_pathActor = NULL;
	}

	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10015e00
// FUNCTION: BETA10 0x100c7b3d
MxLong LegoRace::Notify(MxParam& p_param)
{
	LegoWorld::Notify(p_param);
	MxNotificationParam& param = (MxNotificationParam&) p_param;

	MxLong result = 0;
	if (m_worldStarted) {
		switch (param.GetNotification()) {
		case c_notificationType0:
			HandleType0Notification((MxNotificationParam&) p_param);
			break;
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationControl:
			result = HandleControl((LegoControlManagerNotificationParam&) p_param);
			break;
		case c_notificationPathStruct:
			result = HandlePathStruct((LegoPathStructNotificationParam&) p_param);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(m_destLocation);
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10015ed0
// FUNCTION: BETA10 0x100c7c3f
void LegoRace::Enable(MxBool p_enable)
{
	if (NoDisabledObjects() != p_enable && !p_enable) {
		Remove(UserActor());

		MxU8 oldActorId = GameState()->GetActorId();
		GameState()->RemoveActor();
		GameState()->SetActorId(oldActorId);
	}

	LegoWorld::Enable(p_enable);
}

// FUNCTION: LEGO1 0x10015f30
// FUNCTION: BETA10 0x100c7ca3
RaceState::RaceState()
{
	m_entries[0].m_id = LegoActor::e_pepper;
	m_entries[0].m_lastScore = 0;
	m_entries[0].m_score = 0;
	m_entries[1].m_id = LegoActor::e_mama;
	m_entries[1].m_lastScore = 0;
	m_entries[1].m_score = 0;
	m_entries[2].m_id = LegoActor::e_papa;
	m_entries[2].m_lastScore = 0;
	m_entries[2].m_score = 0;
	m_entries[3].m_id = LegoActor::e_nick;
	m_entries[3].m_lastScore = 0;
	m_entries[3].m_score = 0;
	m_entries[4].m_id = LegoActor::e_laura;
	m_entries[4].m_lastScore = 0;
	m_entries[4].m_score = 0;
	m_state = RaceState::e_carrace;
}

// FUNCTION: LEGO1 0x10016140
// FUNCTION: BETA10 0x100c7d9f
MxResult RaceState::Serialize(LegoStorage* p_storage)
{
	LegoState::Serialize(p_storage);

	for (MxS16 i = 0; i < 5; i++) {
		m_entries[i].Serialize(p_storage);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10016280
// FUNCTION: BETA10 0x100c7dfd
RaceState::Entry* RaceState::GetState(MxU8 p_id)
{
	for (MxS16 i = 0;; i++) {
		if (i >= 5) {
			return NULL;
		}

		if (m_entries[i].m_id == p_id) {
			return m_entries + i;
		}
	}
}

// FUNCTION: LEGO1 0x100162c0
// FUNCTION: BETA10 0x100c7e6f
MxResult JetskiRace::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoRace::Create(p_dsAction);

	GameState()->m_currentArea = LegoGameState::e_jetrace;
	GameState()->StopArea(LegoGameState::e_undefined);
	LegoGameState* gameState = GameState();
	RaceState* jetskiRaceState = (RaceState*) gameState->GetState("JetskiRaceState");

	if (!jetskiRaceState) {
		jetskiRaceState = (RaceState*) gameState->CreateState("JetskiRaceState");
	}

	m_raceState = jetskiRaceState;

	if (!jetskiRaceState) {
		return FAILURE;
	}

	m_raceState->m_state = RaceState::e_jetrace;
	m_progressBarRect.SetLeft(397);
	m_progressBarRect.SetTop(317);
	m_progressBarRect.SetRight(543);
	m_progressBarRect.SetBottom(333);
	LegoJetski::InitSoundIndices();

	MxS32 raceCarDashboardStreamId =
		DuneBuggy::GetColorOffset(g_varJSFRNTY5) + (DuneBuggy::GetColorOffset(g_varJSWNSHY5) * 5 + 0xf) * 2;
	InvokeAction(Extra::e_start, m_atomId, raceCarDashboardStreamId, NULL);
	InvokeAction(Extra::e_start, m_atomId, JetraceScript::c_JetskiDashboard, NULL);

	g_triggerHandlingIgnoreDirection = TRUE;

	return result;
}

// FUNCTION: LEGO1 0x100163b0
// FUNCTION: BETA10 0x100c7f10
void JetskiRace::ReadyWorld()
{
	assert(m_hideAnim);
	LegoWorld::ReadyWorld();
	m_hideAnim->ApplyVisibility(0);

	MxDSAction action;
	action.SetAtomId(*g_jukeboxScript);
	action.SetObjectId(JukeboxScript::c_JetskiRace_Music);
	BackgroundAudioManager()->PlayMusic(action, 5, MxPresenter::e_repeating);

	AnimationManager()->Resume();

	m_opponent1Locator = (MxStillPresenter*) Find("MxPresenter", "JetskiLocator2");
	m_opponent1Locator->SetPosition(m_progressBarRect.GetLeft(), m_progressBarRect.GetTop());
	m_opponent2Locator = (MxStillPresenter*) Find("MxPresenter", "JetskiLocator3");
	m_opponent2Locator->SetPosition(m_progressBarRect.GetLeft(), m_progressBarRect.GetTop());

	Disable(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);

	VariableTable()->SetVariable("DISTANCE", "0.036");

	InvokeAction(Extra::e_start, *g_jetraceScript, JetraceScript::c_AirHorn_PlayWav, NULL);
}

// FUNCTION: LEGO1 0x10016520
MxLong JetskiRace::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	MxLong result = 0;

	if ((p_param.GetAction()) && (p_param.GetAction()->GetObjectId() == JetraceScript::c_AirHorn_PlayWav)) {
		m_mapsLocators[0]->Mute(FALSE);
		m_mapsLocators[1]->Mute(FALSE);
		m_mapsLocators[2]->Mute(FALSE);

		VariableTable()->SetVariable(g_raceState, g_racing);
		result = 1;
	}

	return result;
}

// FUNCTION: LEGO1 0x100165a0
MxLong JetskiRace::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	MxLong result = 0;

	if (p_param.m_enabledChild == 1) {
		switch (p_param.m_clickedObjectId) {
		case JetraceScript::c_JetskiArms_Ctl:
			m_act1State->m_state = Act1State::e_none;
			VariableTable()->SetVariable(g_raceState, "");
			VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
			LegoRaceCar::InitYouCantStopSound();
			m_destLocation = LegoGameState::e_jetraceExterior;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case JetraceScript::c_JetskiInfo_Ctl:
			m_act1State->m_state = Act1State::e_none;
			VariableTable()->SetVariable(g_raceState, "");
			VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
			LegoRaceCar::InitYouCantStopSound();
			m_destLocation = LegoGameState::e_infomain;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			result = 1;
			break;
		default:
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100166a0
// FUNCTION: BETA10 0x100c8085
MxLong JetskiRace::HandlePathStruct(LegoPathStructNotificationParam& p_param)
{
	MxLong result = 0;
	MxEntity* sender = (MxEntity*) p_param.GetSender();

	if (p_param.GetTrigger() == LegoPathStruct::c_waypoint) {
		MxS32 paramData = p_param.GetData();

		switch (sender->GetEntityId()) {
		case JetraceScript::c_UserJetski_Actor:
			if (paramData <= m_playerLastPathStruct || paramData >= m_playerLastPathStruct + 5) {
				break;
			}

			m_playerLastPathStruct = paramData;
			LegoChar buffer[20];
			sprintf(
				buffer,
				"%g",
				0.032 + 0.936 * (m_playerLaps * 20.0 + m_playerLastPathStruct) / (g_lapsCount * 20.0)
			);
			VariableTable()->SetVariable("DISTANCE", buffer);

			if (m_playerLastPathStruct == 0x14) {
				m_playerLastPathStruct = 0;
				m_playerLaps++;

				if (g_lapsCount == m_playerLaps) {
					MxS32 score;

					if (m_opponent1Laps < m_playerLaps && m_opponent2Laps < m_playerLaps) {
						score = 3;
					}
					else if (m_opponent1Laps < m_playerLaps || m_opponent2Laps < m_playerLaps) {
						score = 2;
					}
					else {
						score = 1;
					}

					VariableTable()->SetVariable(g_raceState, "");
					VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
					LegoRaceCar::InitYouCantStopSound();
					m_raceState->m_state = RaceState::e_finished;

					RaceState::Entry* raceStateEntry = m_raceState->GetState(GameState()->GetActorId());
					raceStateEntry->m_lastScore = score;

					if (raceStateEntry->m_score < (MxS16) score) {
						raceStateEntry->m_score = score;
					}

					m_destLocation = LegoGameState::e_jetraceFinished;

					TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
				}

				result = 1;
			}
			else if (m_playerLastPathStruct == 0xf) {
				m_hideAnim->ApplyVisibility(m_playerLaps * 200 + 100);
				result = 1;
			}

			break;
		case JetraceScript::c_Snap_Actor:
			if (paramData <= m_opponent1LastPathStruct || paramData >= m_opponent1LastPathStruct + 5) {
				break;
			}

			SetProgressPosition(JetraceScript::c_Snap_Actor, paramData);
			m_opponent1LastPathStruct = paramData;

			if (m_opponent1LastPathStruct == 0x14) {
				m_opponent1LastPathStruct = 0;
				m_opponent1Laps++;

				if (g_lapsCount == m_opponent1Laps) {
					((LegoPathActor*) p_param.GetSender())->SetMaxLinearVel(0.1);
				}
			}

			break;
		case JetraceScript::c_Valerie_Actor:
			if (paramData <= m_opponent2LastPathStruct || paramData >= m_opponent2LastPathStruct + 5) {
				break;
			}

			SetProgressPosition(JetraceScript::c_Valerie_Actor, paramData);

			m_opponent2LastPathStruct = paramData;

			if (m_opponent2LastPathStruct == 0x14) {
				m_opponent2LastPathStruct = 0;
				m_opponent2Laps++;

				if (g_lapsCount == m_opponent2Laps) {
					((LegoPathActor*) p_param.GetSender())->SetMaxLinearVel(0.1);
				}
			}

			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10016930
void JetskiRace::SetProgressPosition(MxS32 p_actorId, MxS16 p_progress)
{
	MxS32 laps;
	MxStillPresenter* presenter;
	MxS32 x, y;

	if (p_actorId == JetraceScript::c_Snap_Actor) {
		presenter = m_opponent1Locator;
		laps = m_opponent1Laps;
	}
	else if (p_actorId == JetraceScript::c_Valerie_Actor) {
		presenter = m_opponent2Locator;
		laps = m_opponent2Laps;
	}

	if (presenter) {
		x = m_progressBarRect.GetLeft() + 0.5 +
			(m_progressBarRect.GetRight() - m_progressBarRect.GetLeft() + 1) * (laps * 20.0 + p_progress) /
				(g_lapsCount * 20.0);
		y = m_progressBarRect.GetTop() + 0.5 +
			(m_progressBarRect.GetBottom() - m_progressBarRect.GetTop() + 1) * (laps * 20.0 + p_progress) /
				(g_lapsCount * 20.0);

		presenter->SetPosition(x, y);
	}
}

// FUNCTION: LEGO1 0x10016a10
MxBool JetskiRace::Escape()
{
	AnimationManager()->FUN_10061010(FALSE);
	DeleteObjects(&m_atomId, 500, 999);
	m_act1State->m_state = Act1State::e_none;
	VariableTable()->SetVariable(g_raceState, "");
	VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
	m_destLocation = LegoGameState::e_infomain;
	LegoRaceCar::InitYouCantStopSound();
	return TRUE;
}

// FUNCTION: LEGO1 0x10016a90
// FUNCTION: BETA10 0x100c82e8
CarRace::CarRace()
{
	m_skeleton = NULL;
	m_progressBarRect = MxRect32(0x16c, 0x154, 0x1ec, 0x15e);
}

// FUNCTION: LEGO1 0x10016ce0
// FUNCTION: BETA10 0x100c8364
MxResult CarRace::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoRace::Create(p_dsAction);

	NavController()->SetDeadZone(1);
	NavController()->SetTrackDefault(0);
	GameState()->m_currentArea = LegoGameState::e_carrace;
	GameState()->StopArea(LegoGameState::e_undefined);

	LegoGameState* state = GameState();

	RaceState* raceState = (RaceState*) state->GetState("CarRaceState");

	if (!raceState) {
		raceState = (RaceState*) state->CreateState("CarRaceState");
	}

	m_raceState = raceState;

	m_act1State->m_state = Act1State::e_transitionToRacecar;
	m_introAnimation = -1;
	m_firstFinishAnimation = -1;
	m_secondFinishAnimation = -1;

	LegoRaceCar::InitSoundIndices();

	MxS32 raceCarDashboardStreamId =
		DuneBuggy::GetColorOffset(g_strCRCEDGEY0) + (DuneBuggy::GetColorOffset(g_strCRCFRNTY6) * 5 + 15) * 2;
	InvokeAction(Extra::e_start, m_atomId, raceCarDashboardStreamId, NULL);
	InvokeAction(Extra::e_start, m_atomId, CarraceScript::c_RaceCarDashboard, NULL);

	return result;
}

// FUNCTION: LEGO1 0x10016dd0
// FUNCTION: BETA10 0x100c8490
void CarRace::ReadyWorld()
{
	assert(m_hideAnim);
	LegoWorld::ReadyWorld();
	m_hideAnim->ApplyVisibility(0);

	MxDSAction action;
	action.SetAtomId(*g_jukeboxScript);
	action.SetObjectId(JukeboxScript::c_RaceTrackRoad_Music);

	BackgroundAudioManager()->PlayMusic(action, 5, MxPresenter::e_repeating);
	AnimationManager()->Resume();
	Disable(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);

	MxS32 index = rand() & 7;
	m_introAnimation = g_introAnimations[index];

	AnimationManager()
		->FUN_10060dc0(m_introAnimation, NULL, TRUE, LegoAnimationManager::e_unk0, NULL, FALSE, TRUE, FALSE, TRUE);

	m_opponent1Locator = (MxStillPresenter*) Find("MxPresenter", "CarLocator2");
	m_opponent1Locator->SetPosition(m_progressBarRect.GetLeft(), m_progressBarRect.GetTop());

	m_opponent2Locator = (MxStillPresenter*) Find("MxPresenter", "CarLocator3");
	m_opponent2Locator->SetPosition(m_progressBarRect.GetLeft(), m_progressBarRect.GetTop());
	VariableTable()->SetVariable("DISTANCE", "0.036");
}

// FUNCTION: LEGO1 0x10016f60
// FUNCTION: BETA10 0x100c85eb
MxLong CarRace::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	MxLong result = 0;

	if (p_param.GetAction()) {
		MxDSAction* action = p_param.GetAction();
		MxU32 objectId = action->GetObjectId();

		if (m_introAnimation == objectId) {
			InvokeAction(Extra::e_start, *g_carraceScript, CarraceScript::c_irtx08ra_PlayWav, NULL);
			result = 1;
		}
		else if (objectId == CarraceScript::c_irtx08ra_PlayWav && m_destLocation == LegoGameState::e_undefined) {
			m_mapsLocators[0]->Mute(FALSE);
			m_mapsLocators[1]->Mute(FALSE);
			m_mapsLocators[2]->Mute(FALSE);

			VariableTable()->SetVariable(g_raceState, g_racing);
			result = 1;
		}
		else if (m_firstFinishAnimation == objectId) {
			AnimationManager()->FUN_10060dc0(
				m_secondFinishAnimation,
				NULL,
				TRUE,
				LegoAnimationManager::e_unk0,
				NULL,
				FALSE,
				TRUE,
				FALSE,
				TRUE
			);
		}
		else if (m_secondFinishAnimation == objectId) {
			NotificationManager()->Send(this, MxNotificationParam());
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100170e0
// FUNCTION: BETA10 0x100c87ac
MxLong CarRace::HandlePathStruct(LegoPathStructNotificationParam& p_param)
{
	MxLong result = 0;

	if (p_param.GetTrigger() == LegoPathStruct::c_waypoint) {
		MxEntity* sender = (MxEntity*) p_param.GetSender();
		MxS32 paramData = p_param.GetData();

		switch (sender->GetEntityId()) {
		case CarraceScript::c_UserCar_Actor:
			if (paramData <= m_playerLastPathStruct || paramData >= m_playerLastPathStruct + 5) {
				break;
			}

			m_playerLastPathStruct = paramData;
			LegoChar buffer[20];
			sprintf(
				buffer,
				"%g",
				0.036 + 0.928 * (m_playerLaps * 20.0 + m_playerLastPathStruct) / (g_lapsCount * 20.0)
			);
			VariableTable()->SetVariable("DISTANCE", buffer);

			if (m_playerLastPathStruct == 0x14) {
				m_playerLastPathStruct = 0;
				m_playerLaps++;

				if (g_lapsCount == m_playerLaps) {
					VariableTable()->SetVariable(g_raceState, "");

					m_mapsLocators[0]->Mute(TRUE);
					m_mapsLocators[1]->Mute(TRUE);
					m_mapsLocators[2]->Mute(TRUE);

					m_mapsLocators[0]->SetMaxLinearVel(-1.0);
					m_mapsLocators[1]->SetMaxLinearVel(-1.0);
					m_mapsLocators[2]->SetMaxLinearVel(-1.0);

					RemoveActor(m_mapsLocators[1]);
					m_mapsLocators[1]->ClearMaps();

					RemoveActor(m_mapsLocators[2]);
					m_mapsLocators[2]->ClearMaps();

					MxS32 score;

					if (m_opponent1Laps < m_playerLaps && m_opponent2Laps < m_playerLaps) {
						score = 3;
						m_firstFinishAnimation = g_studsLoosesAnimation[rand() % 3];
						m_secondFinishAnimation = g_rhodaLoosesAnimation[rand() % 3];
					}
					else if (m_opponent1Laps < m_playerLaps || m_opponent2Laps < m_playerLaps) {
						score = 2;
						if (m_opponent1Laps == g_lapsCount) {
							m_firstFinishAnimation = g_studsWinsAnimations[rand() % 4];
							m_secondFinishAnimation = g_rhodaLoosesAnimation[rand() % 3];
						}
						else {
							m_firstFinishAnimation = g_rhodaWinsAnimations[rand() % 3];
							m_secondFinishAnimation = g_studsLoosesAnimation[rand() % 3];
						}
					}
					else {
						score = 1;
						m_firstFinishAnimation = g_studsWinsAnimations[rand() % 4];
						m_secondFinishAnimation = g_rhodaWinsAnimations[rand() % 3];
					}

					InputManager()->DisableInputProcessing();
					InputManager()->SetUnknown336(TRUE);
					VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
					NavController()->SetDeadZone(NavController()->GetDefaultDeadZone());
					NavController()->SetTrackDefault(1);
					LegoRaceCar::InitYouCantStopSound();
					m_raceState->m_state = RaceState::e_finished;

					RaceState::Entry* raceState = m_raceState->GetState(GameState()->GetActorId());
					raceState->m_lastScore = score;

					if (raceState->m_score < (MxS16) score) {
						raceState->m_score = score;
					}

					AnimationManager()->FUN_10060dc0(
						m_firstFinishAnimation,
						NULL,
						TRUE,
						LegoAnimationManager::e_unk0,
						NULL,
						FALSE,
						TRUE,
						FALSE,
						TRUE
					);
				}

				result = 1;
			}

			break;
		case CarraceScript::c_Studs_Actor:
			if (paramData <= m_opponent1LastPathStruct || paramData >= m_opponent1LastPathStruct + 5) {
				break;
			}

			SetProgressPosition(CarraceScript::c_Studs_Actor, paramData);
			m_opponent1LastPathStruct = paramData;

			if (m_opponent1LastPathStruct == 0x14) {
				m_opponent1LastPathStruct = 0;
				m_opponent1Laps++;

				if (g_lapsCount == m_opponent1Laps) {
					m_mapsLocators[1]->SetMaxLinearVel(-1.0);
					RemoveActor(m_mapsLocators[1]);
					m_mapsLocators[1]->ClearMaps();
					m_mapsLocators[1]->GetROI()->SetVisibility(FALSE);

					LegoROI* roi = FindROI("rcblack");

					if (roi) {
						roi->SetVisibility(FALSE);
					}
				}
			}

			break;
		case CarraceScript::c_Rhoda_Actor:
			if (paramData <= m_opponent2LastPathStruct || paramData >= m_opponent2LastPathStruct + 5) {
				break;
			}

			SetProgressPosition(CarraceScript::c_Rhoda_Actor, paramData);
			m_opponent2LastPathStruct = paramData;

			if (m_opponent2LastPathStruct == 0x14) {
				m_opponent2LastPathStruct = 0;
				m_opponent2Laps++;

				if (g_lapsCount == m_opponent2Laps) {
					m_mapsLocators[2]->SetMaxLinearVel(-1.0);
					RemoveActor(m_mapsLocators[2]);
					m_mapsLocators[2]->ClearMaps();
					m_mapsLocators[2]->GetROI()->SetVisibility(FALSE);

					LegoROI* roi = FindROI("rcgreen");

					if (roi) {
						roi->SetVisibility(FALSE);
					}
				}
			}

			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10017650
// FUNCTION: BETA10 0x100c8eeb
MxLong CarRace::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	if (p_param.m_enabledChild == 1) {
		switch (p_param.m_clickedObjectId) {
		case 3:
			InvokeAction(Extra::e_stop, *g_carraceScript, CarraceScript::c_irtx08ra_PlayWav, NULL);
			m_act1State->m_state = Act1State::e_none;
			VariableTable()->SetVariable(g_raceState, "");
			VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
			NavController()->SetDeadZone(NavController()->GetDefaultDeadZone());
			NavController()->SetTrackDefault(1);
			LegoRaceCar::InitYouCantStopSound();
			m_destLocation = LegoGameState::e_infomain;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			GameState()->GetBackgroundColor()->SetValue("reset");
			break;
		case 98:
			InvokeAction(Extra::e_stop, *g_carraceScript, CarraceScript::c_irtx08ra_PlayWav, NULL);
			m_act1State->m_state = Act1State::e_none;
			VariableTable()->SetVariable(g_raceState, "");
			VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
			NavController()->SetDeadZone(NavController()->GetDefaultDeadZone());
			NavController()->SetTrackDefault(1);
			LegoRaceCar::InitYouCantStopSound();
			m_destLocation = LegoGameState::e_carraceExterior;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			GameState()->GetBackgroundColor()->SetValue("reset");
			break;
		default:
			break;
		}
	}
	return 1;
}

// FUNCTION: LEGO1 0x100177e0
// FUNCTION: BETA10 0x100c8f59
MxLong CarRace::HandleType0Notification(MxNotificationParam&)
{
	if (m_raceState->m_state == RaceState::e_finished) {
		m_destLocation = LegoGameState::e_carraceFinished;
		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
	}

	return 1;
}

// FUNCTION: LEGO1 0x10017820
void CarRace::SetProgressPosition(MxS32 p_actorId, MxS16 p_progress)
{
	MxS32 laps;
	MxStillPresenter* presenter;
	MxS32 x, y;

	if (p_actorId == CarraceScript::c_Studs_Actor) {
		presenter = m_opponent1Locator;
		laps = m_opponent1Laps;
	}
	else if (p_actorId == CarraceScript::c_Rhoda_Actor) {
		presenter = m_opponent2Locator;
		laps = m_opponent2Laps;
	}

	if (presenter) {
		x = m_progressBarRect.GetLeft() + 0.5 +
			(m_progressBarRect.GetRight() - m_progressBarRect.GetLeft() + 1) * (laps * 20.0 + p_progress) /
				(g_lapsCount * 20.0);
		y = m_progressBarRect.GetTop() + 0.5 +
			(m_progressBarRect.GetBottom() - m_progressBarRect.GetTop() + 1) * (laps * 20.0 + p_progress) /
				(g_lapsCount * 20.0);

		presenter->SetPosition(x, y);
	}
}

// FUNCTION: LEGO1 0x10017900
MxBool CarRace::Escape()
{
	InvokeAction(Extra::e_stop, *g_carraceScript, CarraceScript::c_irtx08ra_PlayWav, NULL);

	AnimationManager()->FUN_10061010(FALSE);
	DeleteObjects(&m_atomId, 500, 999);
	m_act1State->m_state = Act1State::e_none;
	VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");

	VariableTable()->SetVariable(g_raceState, "");
	NavController()->SetDeadZone(NavController()->GetDefaultDeadZone());

	NavController()->SetTrackDefault(1);
	LegoRaceCar::InitYouCantStopSound();

	GameState()->GetBackgroundColor()->SetValue("reset");
	m_destLocation = LegoGameState::e_infomain;
	return TRUE;
}
