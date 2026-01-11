#include "jetskirace.h"

#include "dunebuggy.h"
#include "isle.h"
#include "jetrace_actions.h"
#include "jetski_actions.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legoanimpresenter.h"
#include "legocontrolmanager.h"
#include "legomain.h"
#include "legopathstruct.h"
#include "legoracers.h"
#include "legoracespecial.h"
#include "legoutils.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxstillpresenter.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"
#include "scripts.h"

// Defined in legopathstruct.cpp
extern MxBool g_unk0x100f119c;

// Defined in jetski.cpp
extern const char* g_varJSFRNTY5;
extern const char* g_varJSWNSHY5;

// Defined in legopathactor.cpp
extern const char* g_strHIT_WALL_SOUND;

DECOMP_SIZE_ASSERT(JetskiRace, 0x144)

// GLOBAL: LEGO1 0x100f0c78
MxS32 JetskiRace::g_lapsCount = 2;

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

	g_unk0x100f119c = TRUE;

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
			result = 1;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
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

	if (p_param.GetTrigger() == LegoPathStruct::c_d) {
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
