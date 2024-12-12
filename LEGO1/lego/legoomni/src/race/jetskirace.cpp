#include "jetskirace.h"

#include "dunebuggy.h"
#include "isle.h"
#include "jetrace_actions.h"
#include "jetski_actions.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legocontrolmanager.h"
#include "legohideanimpresenter.h"
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
MxS32 JetskiRace::g_unk0x100f0c78 = 2;

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

	m_raceState->m_unk0x28 = 1;
	m_unk0x130.SetLeft(397);
	m_unk0x130.SetTop(317);
	m_unk0x130.SetRight(543);
	m_unk0x130.SetBottom(333);
	LegoRaceCar::FUN_10013670();
	InvokeAction(
		Extra::e_start,
		m_atomId,
		DuneBuggy::GetColorOffset(g_varJSFRNTY5) + (DuneBuggy::GetColorOffset(g_varJSWNSHY5) * 5 + 0xf) * 2,
		NULL
	);
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
	m_hideAnim->FUN_1006db40(0);

	MxDSAction action;
	action.SetAtomId(*g_jukeboxScript);
	action.SetObjectId(JukeboxScript::c_JetskiRace_Music);
	BackgroundAudioManager()->PlayMusic(action, 5, MxPresenter::e_repeating);

	AnimationManager()->Resume();

	m_unk0x128 = (MxStillPresenter*) Find("MxPresenter", "JetskiLocator2");
	m_unk0x128->SetPosition(m_unk0x130.GetLeft(), m_unk0x130.GetTop());
	m_unk0x12c = (MxStillPresenter*) Find("MxPresenter", "JetskiLocator3");
	m_unk0x12c->SetPosition(m_unk0x130.GetLeft(), m_unk0x130.GetTop());

	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);

	VariableTable()->SetVariable("DISTANCE", "0.036");

	InvokeAction(Extra::e_start, *g_jetraceScript, JetraceScript::c_AirHorn_PlayWav, NULL);
}

// FUNCTION: LEGO1 0x10016520
MxLong JetskiRace::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	MxLong result = 0;

	if ((p_param.GetAction()) && (p_param.GetAction()->GetObjectId() == JetraceScript::c_AirHorn_PlayWav)) {
		m_maps[0]->Mute(FALSE);
		m_maps[1]->Mute(FALSE);
		m_maps[2]->Mute(FALSE);

		VariableTable()->SetVariable(g_raceState, g_racing);
		result = 1;
	}

	return result;
}

// FUNCTION: LEGO1 0x100165a0
MxLong JetskiRace::HandleClick(LegoEventNotificationParam& p_param)
{
	MxLong result = 0;

	if (((LegoControlManagerNotificationParam*) &p_param)->m_unk0x28 == 1) {
		switch (((LegoControlManagerNotificationParam*) &p_param)->m_clickedObjectId) {
		case JetraceScript::c_JetskiArms_Ctl:
			m_act1State->m_unk0x018 = 0;
			VariableTable()->SetVariable(g_raceState, "");
			VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
			LegoRaceCar::FUN_10012de0();
			m_destLocation = LegoGameState::e_jetraceExterior;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case JetraceScript::c_JetskiInfo_Ctl:
			m_act1State->m_unk0x018 = 0;
			VariableTable()->SetVariable(g_raceState, "");
			VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
			LegoRaceCar::FUN_10012de0();
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

	if (p_param.GetTrigger() == 68) {
		MxS32 paramData = p_param.GetData();

		switch (sender->GetEntityId()) {
		case 10:
			if (paramData <= m_unk0x104 || paramData >= m_unk0x104 + 5) {
				break;
			}

			m_unk0x104 = paramData;
			LegoChar buffer[20];
			sprintf(buffer, "%g", 0.032 + 0.936 * (m_unk0xf8 * 20.0 + m_unk0x104) / (g_unk0x100f0c78 * 20.0));
			VariableTable()->SetVariable("DISTANCE", buffer);

			if (m_unk0x104 == 0x14) {
				m_unk0x104 = 0;
				m_unk0xf8++;

				if (g_unk0x100f0c78 == m_unk0xf8) {
					MxS32 position;

					if (m_unk0xfc < m_unk0xf8 && m_unk0x100 < m_unk0xf8) {
						position = 3;
					}
					else if (m_unk0xfc < m_unk0xf8 || m_unk0x100 < m_unk0xf8) {
						position = 2;
					}
					else {
						position = 1;
					}

					VariableTable()->SetVariable(g_raceState, "");
					VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
					LegoRaceCar::FUN_10012de0();
					m_raceState->m_unk0x28 = 2;

					RaceState::Entry* raceStateEntry = m_raceState->GetState(GameState()->GetActorId());
					raceStateEntry->m_unk0x02 = position;

					if (raceStateEntry->m_score < (MxS16) position) {
						raceStateEntry->m_score = position;
					}

					m_destLocation = LegoGameState::e_jetrace2;

					TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
				}

				result = 1;
			}
			else if (m_unk0x104 == 0xf) {
				m_hideAnim->FUN_1006db40(m_unk0xf8 * 200 + 100);
				result = 1;
			}

			break;
		case 11:
			if (paramData <= m_unk0x108 || paramData >= m_unk0x108 + 5) {
				break;
			}

			FUN_10016930(11, paramData);
			m_unk0x108 = paramData;

			if (m_unk0x108 == 0x14) {
				m_unk0x108 = 0;
				m_unk0xfc++;

				if (g_unk0x100f0c78 == m_unk0xfc) {
					((LegoPathActor*) p_param.GetSender())->SetMaxLinearVel(0.1);
				}
			}

			break;
		case 12:
			if (paramData <= m_unk0x10c || paramData >= m_unk0x10c + 5) {
				break;
			}

			FUN_10016930(12, paramData);

			m_unk0x10c = paramData;

			if (m_unk0x10c == 0x14) {
				m_unk0x10c = 0;
				m_unk0x100++;

				if (g_unk0x100f0c78 == m_unk0x100) {
					((LegoPathActor*) p_param.GetSender())->SetMaxLinearVel(0.1);
				}
			}

			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10016930
void JetskiRace::FUN_10016930(MxS32 p_param1, MxS16 p_param2)
{
	MxS32 local4;
	MxStillPresenter* presenter;
	MxS32 x, y;

	if (p_param1 == 11) {
		presenter = m_unk0x128;
		local4 = m_unk0xfc;
	}
	else if (p_param1 == 12) {
		presenter = m_unk0x12c;
		local4 = m_unk0x100;
	}

	if (presenter) {
		x = m_unk0x130.GetLeft() + 0.5 +
			(m_unk0x130.GetRight() - m_unk0x130.GetLeft() + 1) * (local4 * 20.0 + p_param2) / (g_unk0x100f0c78 * 20.0);
		y = m_unk0x130.GetTop() + 0.5 +
			(m_unk0x130.GetBottom() - m_unk0x130.GetTop() + 1) * (local4 * 20.0 + p_param2) / (g_unk0x100f0c78 * 20.0);

		presenter->SetPosition(x, y);
	}
}

// FUNCTION: LEGO1 0x10016a10
MxBool JetskiRace::Escape()
{
	AnimationManager()->FUN_10061010(FALSE);
	DeleteObjects(&m_atomId, 500, 999);
	m_act1State->m_unk0x018 = 0;
	VariableTable()->SetVariable(g_raceState, "");
	VariableTable()->SetVariable(g_strHIT_WALL_SOUND, "");
	m_destLocation = LegoGameState::e_infomain;
	LegoRaceCar::FUN_10012de0();
	return TRUE;
}
