#include "carrace.h"

#include "carrace_actions.h"
#include "dunebuggy.h"
#include "isle.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legoanimpresenter.h"
#include "legocontrolmanager.h"
#include "legomain.h"
#include "legonavcontroller.h"
#include "legopathstruct.h"
#include "legoracers.h"
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

DECOMP_SIZE_ASSERT(CarRace, 0x154)

// GLOBAL: LEGO1 0x100d5d10
MxS32 CarRace::g_introAnimations[] = {
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
MxS32 CarRace::g_unk0x100d5d30[] = {
	CarraceScript::c_srt011sl_RunAnim,
	CarraceScript::c_srt012sl_RunAnim,
	CarraceScript::c_srt013sl_RunAnim,
	CarraceScript::c_srt014sl_RunAnim
};

// GLOBAL: LEGO1 0x100d5d40
MxS32 CarRace::g_unk0x100d5d40[] =
	{CarraceScript::c_srt015sl_RunAnim, CarraceScript::c_srt016sl_RunAnim, CarraceScript::c_srt017sl_RunAnim};

// GLOBAL: LEGO1 0x100d5d50
MxS32 CarRace::g_unk0x100d5d50[] =
	{CarraceScript::c_srt007rh_RunAnim, CarraceScript::c_srt008rh_RunAnim, CarraceScript::c_srt009rh_RunAnim};

// GLOBAL: LEGO1 0x100d5d60
MxS32 CarRace::g_unk0x100d5d60[] =
	{CarraceScript::c_srt010rh_RunAnim, CarraceScript::c_srt011rh_RunAnim, CarraceScript::c_srt012rh_RunAnim};

// GLOBAL: LEGO1 0x100f0c70
// STRING: LEGO1 0x100f0c48
const LegoChar* g_strCRCFRNTY6 = "C_RCFRNTY6";

// GLOBAL: LEGO1 0x100f0c74
// STRING: LEGO1 0x100f0c3c
const LegoChar* g_strCRCEDGEY0 = "C_RCEDGEY0";

// GLOBAL: LEGO1 0x100f0c7c
MxS32 g_unk0x100f0c7c = 2;

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
	m_unk0x148 = -1;
	m_unk0x14c = -1;

	LegoRaceCar::InitSoundIndices();

	MxS32 streamId =
		DuneBuggy::GetColorOffset(g_strCRCEDGEY0) + (DuneBuggy::GetColorOffset(g_strCRCFRNTY6) * 5 + 15) * 2;
	InvokeAction(Extra::e_start, m_atomId, streamId, NULL);
	InvokeAction(Extra::e_start, m_atomId, CarraceScript::c_RaceCarDashboard, NULL);

	return result;
}

// FUNCTION: LEGO1 0x10016dd0
// FUNCTION: BETA10 0x100c8490
void CarRace::ReadyWorld()
{
	assert(m_hideAnim);
	LegoWorld::ReadyWorld();
	m_hideAnim->FUN_1006db40(0);

	MxDSAction action;
	action.SetAtomId(*g_jukeboxScript);
	action.SetObjectId(JukeboxScript::c_RaceTrackRoad_Music);

	BackgroundAudioManager()->PlayMusic(action, 5, MxPresenter::e_repeating);
	AnimationManager()->Resume();
	Disable(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);

	m_introAnimation = g_introAnimations[rand() & 7];

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
		else if (m_unk0x148 == objectId) {
			AnimationManager()
				->FUN_10060dc0(m_unk0x14c, NULL, TRUE, LegoAnimationManager::e_unk0, NULL, FALSE, TRUE, FALSE, TRUE);
		}
		else if (m_unk0x14c == objectId) {
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

	if (p_param.GetTrigger() == LegoPathStruct::c_d) {
		MxEntity* sender = (MxEntity*) p_param.GetSender();
		MxS32 paramData = p_param.GetData();

		switch (sender->GetEntityId()) {
		case 10:
			if (paramData <= m_playerLastPathStruct || paramData >= m_playerLastPathStruct + 5) {
				break;
			}

			m_playerLastPathStruct = paramData;
			LegoChar buffer[20];
			sprintf(
				buffer,
				"%g",
				0.036 + 0.928 * (m_playerLaps * 20.0 + m_playerLastPathStruct) / (g_unk0x100f0c7c * 20.0)
			);
			VariableTable()->SetVariable("DISTANCE", buffer);

			if (m_playerLastPathStruct == 0x14) {
				m_playerLastPathStruct = 0;
				m_playerLaps++;

				if (g_unk0x100f0c7c == m_playerLaps) {
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

					MxS32 position;

					if (m_opponent1Laps < m_playerLaps && m_opponent2Laps < m_playerLaps) {
						position = 3;
						m_unk0x148 = g_unk0x100d5d40[rand() % 3];
						m_unk0x14c = g_unk0x100d5d60[rand() % 3];
					}
					else if (m_opponent1Laps < m_playerLaps || m_opponent2Laps < m_playerLaps) {
						position = 2;
						if (m_opponent1Laps == g_unk0x100f0c7c) {
							m_unk0x148 = g_unk0x100d5d30[rand() % 4];
							m_unk0x14c = g_unk0x100d5d60[rand() % 3];
						}
						else {
							m_unk0x148 = g_unk0x100d5d50[rand() % 3];
							m_unk0x14c = g_unk0x100d5d40[rand() % 3];
						}
					}
					else {
						position = 1;
						m_unk0x148 = g_unk0x100d5d30[rand() % 4];
						m_unk0x14c = g_unk0x100d5d50[rand() % 3];
					}

					InputManager()->DisableInputProcessing();
					InputManager()->SetUnknown336(TRUE);
					VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
					NavController()->SetDeadZone(NavController()->GetDefaultDeadZone());
					NavController()->SetTrackDefault(1);
					LegoRaceCar::InitYouCantStopSound();
					m_raceState->m_state = RaceState::e_finished;

					RaceState::Entry* raceState = m_raceState->GetState(GameState()->GetActorId());
					raceState->m_lastScore = position;

					if (raceState->m_score < (MxS16) position) {
						raceState->m_score = position;
					}

					AnimationManager()->FUN_10060dc0(
						m_unk0x148,
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
		case 11:
			if (paramData <= m_opponent1LastPathStruct || paramData >= m_opponent1LastPathStruct + 5) {
				break;
			}

			FUN_10017820(11, paramData);
			m_opponent1LastPathStruct = paramData;

			if (m_opponent1LastPathStruct == 0x14) {
				m_opponent1LastPathStruct = 0;
				m_opponent1Laps++;

				if (g_unk0x100f0c7c == m_opponent1Laps) {
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
		case 12:
			if (paramData <= m_opponent2LastPathStruct || paramData >= m_opponent2LastPathStruct + 5) {
				break;
			}

			FUN_10017820(12, paramData);
			m_opponent2LastPathStruct = paramData;

			if (m_opponent2LastPathStruct == 0x14) {
				m_opponent2LastPathStruct = 0;
				m_opponent2Laps++;

				if (g_unk0x100f0c7c == m_opponent2Laps) {
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
		m_destLocation = LegoGameState::e_unk21;
		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
	}

	return 1;
}

// FUNCTION: LEGO1 0x10017820
void CarRace::FUN_10017820(MxS32 p_param1, MxS16 p_param2)
{
	MxS32 local4;
	MxStillPresenter* presenter;
	MxS32 x, y;

	if (p_param1 == 11) {
		presenter = m_opponent1Locator;
		local4 = m_opponent1Laps;
	}
	else if (p_param1 == 12) {
		presenter = m_opponent2Locator;
		local4 = m_opponent2Laps;
	}

	if (presenter) {
		x = m_progressBarRect.GetLeft() + 0.5 +
			(m_progressBarRect.GetRight() - m_progressBarRect.GetLeft() + 1) * (local4 * 20.0 + p_param2) /
				(g_unk0x100f0c7c * 20.0);
		y = m_progressBarRect.GetTop() + 0.5 +
			(m_progressBarRect.GetBottom() - m_progressBarRect.GetTop() + 1) * (local4 * 20.0 + p_param2) /
				(g_unk0x100f0c7c * 20.0);

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
