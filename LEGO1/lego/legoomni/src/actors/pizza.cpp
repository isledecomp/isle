#include "pizza.h"

#include "isle.h"
#include "isle_actions.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legogamestate.h"
#include "legopathstruct.h"
#include "legoutils.h"
#include "legoworld.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "pizzeria.h"
#include "skateboard.h"
#include "sndanim_actions.h"

DECOMP_SIZE_ASSERT(Pizza, 0x9c)
DECOMP_SIZE_ASSERT(PizzaMissionState, 0xb4)
DECOMP_SIZE_ASSERT(PizzaMissionState::Mission, 0x20)

// Flags used in isle.cpp
extern MxU32 g_isleFlags;

// GLOBAL: LEGO1 0x100f3a80
IsleScript::Script PizzaMissionState::g_pepperActions[] = {
	IsleScript::c_pnsx48pr_RunAnim,
	IsleScript::c_pnsx69pr_RunAnim,
	IsleScript::c_pns125ni_RunAnim,
	IsleScript::c_pns122pr_RunAnim,
	IsleScript::c_noneIsle,
	IsleScript::c_noneIsle,
	IsleScript::c_ppz120pa_RunAnim,
	IsleScript::c_ppz117ma_RunAnim,
	IsleScript::c_ppz118ma_RunAnim,
	IsleScript::c_ppz119ma_RunAnim,
	IsleScript::c_nja001pr_RunAnim,
	IsleScript::c_nja001pr_RunAnim,
	IsleScript::c_nja001pr_RunAnim
};

// GLOBAL: LEGO1 0x100f3ab8
MxLong PizzaMissionState::g_pepperFinishTimes[] = {100000, 200000, 300000, 350000};

// GLOBAL: LEGO1 0x100f3ac8
IsleScript::Script PizzaMissionState::g_lauraActions[] = {
	IsleScript::c_pns096pr_RunAnim,
	IsleScript::c_pns097pr_RunAnim,
	IsleScript::c_pns098pr_RunAnim,
	IsleScript::c_pns099pr_RunAnim,
	IsleScript::c_noneIsle,
	IsleScript::c_ppz086bs_RunAnim,
	IsleScript::c_ppz090ma_RunAnim,
	IsleScript::c_ppz088ma_RunAnim,
	IsleScript::c_ppz089ma_RunAnim,
	IsleScript::c_ppz095pe_RunAnim,
	IsleScript::c_pho104re_RunAnim,
	IsleScript::c_pho105re_RunAnim,
	IsleScript::c_pho106re_RunAnim
};

// GLOBAL: LEGO1 0x100f3b00
MxLong PizzaMissionState::g_lauraFinishTimes[] = {100000, 200000, 300000, 350000};

// GLOBAL: LEGO1 0x100f3b10
IsleScript::Script PizzaMissionState::g_nickActions[] = {
	IsleScript::c_pns042bm_RunAnim,
	IsleScript::c_pns043en_RunAnim,
	IsleScript::c_pns045p1_RunAnim,
	IsleScript::c_pns048pr_RunAnim,
	IsleScript::c_ppz029rd_RunAnim,
	IsleScript::c_noneIsle,
	IsleScript::c_ppz038ma_RunAnim,
	IsleScript::c_ppz037ma_RunAnim,
	IsleScript::c_ppz037ma_RunAnim,
	IsleScript::c_ppz037ma_RunAnim,
	IsleScript::c_pgs050nu_RunAnim,
	IsleScript::c_pgs051nu_RunAnim,
	IsleScript::c_pgs052nu_RunAnim
};

// GLOBAL: LEGO1 0x100f3b48
MxLong PizzaMissionState::g_nickFinishTimes[] = {100000, 200000, 300000, 350000};

// GLOBAL: LEGO1 0x100f3b58
IsleScript::Script PizzaMissionState::g_mamaActions[] = {
	IsleScript::c_pns022pr_RunAnim,
	IsleScript::c_pns021dl_RunAnim,
	IsleScript::c_pns018rd_RunAnim,
	IsleScript::c_pns019pr_RunAnim,
	IsleScript::c_ppz008rd_RunAnim,
	IsleScript::c_noneIsle,
	IsleScript::c_ppz013pa_RunAnim,
	IsleScript::c_ppz010pa_RunAnim,
	IsleScript::c_ppz011pa_RunAnim,
	IsleScript::c_ppz016pe_RunAnim,
	IsleScript::c_pps025ni_RunAnim,
	IsleScript::c_pps026ni_RunAnim,
	IsleScript::c_pps027ni_RunAnim
};

// GLOBAL: LEGO1 0x100f3b90
MxLong PizzaMissionState::g_mamaFinishTimes[] = {100000, 200000, 300000, 350000};

// GLOBAL: LEGO1 0x100f3ba0
IsleScript::Script PizzaMissionState::g_papaActions[] = {
	IsleScript::c_pns065rd_RunAnim,
	IsleScript::c_pns066db_RunAnim,
	IsleScript::c_pns067gd_RunAnim,
	IsleScript::c_pns069pr_RunAnim,
	IsleScript::c_noneIsle,
	IsleScript::c_noneIsle,
	IsleScript::c_ppz061ma_RunAnim,
	IsleScript::c_ppz059ma_RunAnim,
	IsleScript::c_ppz060ma_RunAnim,
	IsleScript::c_ppz064ma_RunAnim,
	IsleScript::c_prt072sl_RunAnim,
	IsleScript::c_prt073sl_RunAnim,
	IsleScript::c_prt074sl_RunAnim
};

// GLOBAL: LEGO1 0x100f3bd8
MxLong PizzaMissionState::g_papaFinishTimes[] = {100000, 200000, 300000, 350000};

// FUNCTION: LEGO1 0x10037ef0
Pizza::Pizza()
{
	m_state = NULL;
	m_mission = NULL;
	m_skateBoard = NULL;
	m_act1state = NULL;
	m_unk0x8c = IsleScript::c_noneIsle;
	m_unk0x98 = FALSE;
	m_unk0x90 = INT_MIN;
}

// FUNCTION: LEGO1 0x10038100
Pizza::~Pizza()
{
	TickleManager()->UnregisterClient(this);
}

// FUNCTION: LEGO1 0x10038170
MxResult Pizza::Create(MxDSAction& p_dsAction)
{
	MxResult result = IsleActor::Create(p_dsAction);

	if (result == SUCCESS) {
		CreateState();
		m_skateBoard = (SkateBoard*) m_world->Find(m_atomId, IsleScript::c_SkateBoard_Actor);
	}

	return result;
}

// FUNCTION: LEGO1 0x100381b0
// FUNCTION: BETA10 0x100edaec
void Pizza::CreateState()
{
	m_state = (PizzaMissionState*) GameState()->GetState("PizzaMissionState");
	if (m_state == NULL) {
		m_state = (PizzaMissionState*) GameState()->CreateState("PizzaMissionState");
	}

	m_act1state = (Act1State*) GameState()->GetState("Act1State");
	if (m_act1state == NULL) {
		m_act1state = (Act1State*) GameState()->CreateState("Act1State");
	}
}

// FUNCTION: LEGO1 0x10038220
// FUNCTION: BETA10 0x100edb81
void Pizza::FUN_10038220(IsleScript::Script p_objectId)
{
	AnimationManager()->FUN_10064740(NULL);
	m_mission = m_state->GetMission(GameState()->GetActorId());
	m_state->m_unk0x0c = 1;
	m_act1state->m_unk0x018 = 3;
	m_mission->m_startTime = INT_MIN;
	g_isleFlags &= ~Isle::c_playMusic;
	AnimationManager()->EnableCamAnims(FALSE);
	AnimationManager()->FUN_1005f6d0(FALSE);
	PlayAction(p_objectId, FALSE);
	m_unk0x8c = IsleScript::c_noneIsle;
}

// FUNCTION: LEGO1 0x100382b0
void Pizza::FUN_100382b0()
{
	if (m_state->m_unk0x0c != 8) {
		if (m_unk0x8c != IsleScript::c_noneIsle) {
			InvokeAction(Extra::e_stop, *g_isleScript, m_unk0x8c, NULL);
		}

		m_act1state->m_unk0x018 = 0;
		m_state->m_unk0x0c = 0;
		UserActor()->SetState(0);
		g_isleFlags |= Isle::c_playMusic;
		AnimationManager()->EnableCamAnims(TRUE);
		AnimationManager()->FUN_1005f6d0(TRUE);
		m_mission->m_startTime = INT_MIN;
		m_mission = NULL;
		m_unk0x98 = FALSE;
		m_unk0x8c = IsleScript::c_noneIsle;
		BackgroundAudioManager()->RaiseVolume();
		TickleManager()->UnregisterClient(this);
		m_unk0x90 = INT_MIN;
		m_skateBoard->EnableScenePresentation(FALSE);
		m_skateBoard->SetUnknown0x160(FALSE);
	}
}

// FUNCTION: LEGO1 0x10038380
void Pizza::StopActions()
{
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_pns050p1_RunAnim, NULL);
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_wns050p1_RunAnim, NULL);

	PizzaMissionState::Mission* mission = m_mission;
	if (mission != NULL) {
		for (MxS32 i = 0; i < mission->m_numActions; i++) {
			InvokeAction(Extra::e_stop, *g_isleScript, mission->m_actions[i], NULL);
		}
	}
}

// FUNCTION: LEGO1 0x100383f0
// FUNCTION: BETA10 0x100edd10
MxLong Pizza::HandleClick()
{
	if (m_state->m_unk0x0c == 1) {
		m_state->m_unk0x0c = 2;
		m_mission->m_startTime = Timer()->GetTime();
		TickleManager()->RegisterClient(this, 200);
		AnimationManager()->FUN_10061010(FALSE);
	}

	if (m_state->m_unk0x0c == 2) {
		m_act1state->m_unk0x018 = 3;

		if (m_skateBoard == NULL) {
			m_skateBoard = (SkateBoard*) m_world->Find(m_atomId, IsleScript::c_SkateBoard_Actor);
		}

		IsleScript::Script action;

		switch (m_state->FUN_10039540()) {
		case 0:
			action = m_mission->m_actions[m_mission->m_numActions + 3];
			break;
		case 1:
			action = m_mission->m_actions[m_mission->m_numActions + 4];
			break;
		default:
			action = m_mission->m_actions[m_mission->m_numActions + 5];
		}

		PlayAction(action, TRUE);
		m_state->m_unk0x0c = 3;
		PlayMusic(JukeboxScript::c_PizzaMission_Music);
		return 1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x100384f0
// FUNCTION: BETA10 0x100ede53
MxLong Pizza::HandlePathStruct(LegoPathStructNotificationParam& p_param)
{
	if (m_state->m_unk0x0c == 4) {
		MxLong time = Timer()->GetTime() - m_mission->m_startTime;

		if (p_param.GetTrigger() == LegoPathStruct::c_s && p_param.GetData() == 0x12e &&
			GameState()->GetActorId() == LegoActor::c_pepper) {
			m_state->m_unk0x0c = 5;
			m_state->SetUnknown0xb0(SndanimScript::c_TRS302_OpenJailDoor);

			if (time < m_mission->GetRedFinishTime()) {
				m_mission->UpdateScore(LegoState::e_red);
			}
			else if (time < m_mission->GetBlueFinishTime()) {
				m_mission->UpdateScore(LegoState::e_blue);
			}
			else {
				m_mission->UpdateScore(LegoState::e_yellow);
			}
		}
		else if ((p_param.GetTrigger() == LegoPathStruct::c_camAnim && (
			((p_param.GetData() == 0x24 || p_param.GetData() == 0x22) && GameState()->GetActorId() == LegoActor::c_mama) ||
			(p_param.GetData() == 0x33 && GameState()->GetActorId() == LegoActor::c_papa) ||
			((p_param.GetData() == 0x08 || p_param.GetData() == 0x09) && GameState()->GetActorId() == LegoActor::c_nick) ||
			(p_param.GetData() == 0x0b && GameState()->GetActorId() == LegoActor::c_laura)
		)) || (p_param.GetTrigger() == LegoPathStruct::c_w && p_param.GetData() == 0x169 && GameState()->GetActorId() == LegoActor::c_nick)) {
			IsleScript::Script action;

			if (time < m_mission->GetRedFinishTime()) {
				action = m_mission->GetRedFinishAction();
				m_mission->UpdateScore(LegoState::e_red);
			}
			else if (time < m_mission->GetBlueFinishTime()) {
				action = m_mission->GetBlueFinishAction();
				m_mission->UpdateScore(LegoState::e_blue);
			}
			else {
				action = m_mission->GetYellowFinishAction();
				m_mission->UpdateScore(LegoState::e_yellow);
			}

			StopActions();

			switch (action) {
			case IsleScript::c_pps025ni_RunAnim:
			case IsleScript::c_pps026ni_RunAnim:
			case IsleScript::c_pps027ni_RunAnim:
				m_unk0x90 = Timer()->GetTime();
				m_unk0x94 = 3800;
				break;
			case IsleScript::c_pgs050nu_RunAnim:
			case IsleScript::c_pgs051nu_RunAnim:
			case IsleScript::c_pgs052nu_RunAnim:
				m_unk0x90 = Timer()->GetTime();
				m_unk0x94 = 6400;
				break;
			case IsleScript::c_prt072sl_RunAnim:
			case IsleScript::c_prt073sl_RunAnim:
			case IsleScript::c_prt074sl_RunAnim:
				m_unk0x90 = Timer()->GetTime();
				m_unk0x94 = 7000;
				break;
			case IsleScript::c_pho104re_RunAnim:
			case IsleScript::c_pho105re_RunAnim:
			case IsleScript::c_pho106re_RunAnim:
				m_unk0x90 = Timer()->GetTime();
				m_unk0x94 = 6500;
				break;
			}

			m_state->m_unk0x0c = 5;
			PlayAction(action, TRUE);
		}
		else if (p_param.GetTrigger() == LegoPathStruct::c_w) {
			if (p_param.GetData() == 0x15e && GameState()->GetActorId() == LegoActor::c_pepper) {
				if (!m_unk0x98) {
					m_unk0x98 = TRUE;
					InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_pns050p1_RunAnim, NULL);
				}
			}
			else if (p_param.GetData() == 0x15f && GameState()->GetActorId() == LegoActor::c_papa && !m_unk0x98) {
				m_unk0x98 = TRUE;
				InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_wns050p1_RunAnim, NULL);
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x100388a0
// FUNCTION: BETA10 0x100ee2d9
MxResult Pizza::Tickle()
{
	MxLong time = Timer()->GetTime();

	if (m_unk0x90 != INT_MIN && m_unk0x94 + m_unk0x90 <= time) {
		m_unk0x90 = INT_MIN;
		m_skateBoard->EnableScenePresentation(FALSE);
		m_skateBoard->SetUnknown0x160(FALSE);
		TickleManager()->UnregisterClient(this);
	}

	if (m_mission != NULL && m_mission->m_startTime != INT_MIN) {
		if (m_state->m_unk0x0c == 4) {
			if (time > m_mission->m_startTime + m_mission->GetTimeoutTime()) {
				StopActions();
				m_mission->UpdateScore(LegoState::e_grey);
				FUN_100382b0();
				BackgroundAudioManager()->LowerVolume();
				InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_Avo917In_PlayWav, NULL);
			}
			else if (time >= m_mission->m_startTime + 35000 && m_unk0x8c == IsleScript::c_noneIsle) {
				switch (GameState()->GetActorId()) {
				case LegoActor::c_pepper:
					m_unk0x8c = IsleScript::c_Avo914In_PlayWav;
					break;
				case LegoActor::c_mama:
					m_unk0x8c = IsleScript::c_Avo910In_PlayWav;
					break;
				case LegoActor::c_papa:
					m_unk0x8c = IsleScript::c_Avo912In_PlayWav;
					break;
				case LegoActor::c_nick:
					m_unk0x8c = IsleScript::c_Avo911In_PlayWav;
					break;
				case LegoActor::c_laura:
					m_unk0x8c = IsleScript::c_Avo913In_PlayWav;
					break;
				}

				BackgroundAudioManager()->LowerVolume();

				if (m_unk0x8c != IsleScript::c_noneIsle) {
					InvokeAction(Extra::e_start, *g_isleScript, m_unk0x8c, NULL);
				}
			}
		}
		else if (m_state->m_unk0x0c == 2) {
			if (Timer()->GetTime() > m_mission->m_startTime + 5000) {
				m_skateBoard->SetUnknown0x160(FALSE);
				m_skateBoard->EnableScenePresentation(FALSE);
				TickleManager()->UnregisterClient(this);
				m_mission->UpdateScore(LegoState::e_grey);
				m_state->m_unk0x0c = 9;
				AnimationManager()->FUN_1005f6d0(TRUE);
				PlayAction(m_mission->GetUnknownFinishAction(), TRUE);
			}
		}
	}

	return SUCCESS;
}

// STUB: LEGO1 0x10038b10
MxLong Pizza::HandleEndAction(MxEndActionNotificationParam&)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10038fe0
// FUNCTION: BETA10 0x100ef520
void Pizza::PlayAction(MxU32 p_objectId, MxBool p_param7)
{
	m_state->SetUnknown0xb0(p_objectId);

	if (m_unk0x8c != IsleScript::c_noneIsle) {
		InvokeAction(Extra::e_stop, *g_isleScript, m_unk0x8c, NULL);
	}

	AnimationManager()->FUN_10060dc0(p_objectId, NULL, TRUE, FALSE, NULL, FALSE, p_param7, TRUE, TRUE);
}

// FUNCTION: LEGO1 0x10039030
// FUNCTION: BETA10 0x100eea25
PizzaMissionState::PizzaMissionState()
{
	m_unk0x0c = 0;
	m_missions[0] = Mission(LegoActor::c_pepper, 2, g_pepperFinishTimes, g_pepperActions, 4);
	m_missions[1] = Mission(LegoActor::c_mama, 2, g_mamaFinishTimes, g_mamaActions, 4);
	m_missions[2] = Mission(LegoActor::c_papa, 2, g_papaFinishTimes, g_papaActions, 4);
	m_missions[3] = Mission(LegoActor::c_nick, 2, g_nickFinishTimes, g_nickActions, 4);
	m_missions[4] = Mission(LegoActor::c_laura, 2, g_lauraFinishTimes, g_lauraActions, 4);
	m_pizzeriaState = (PizzeriaState*) GameState()->GetState("PizzeriaState");
	m_unk0xb0 = IsleScript::c_noneIsle;
}

// FUNCTION: LEGO1 0x100393c0
MxResult PizzaMissionState::Serialize(LegoFile* p_file)
{
	LegoState::Serialize(p_file);

	if (p_file->IsReadMode()) {
		for (MxS16 i = 0; i < 5; i++) {
			m_missions[i].ReadFromFile(p_file);
		}
	}
	else if (p_file->IsWriteMode()) {
		for (MxS16 i = 0; i < 5; i++) {
			m_missions[i].WriteToFile(p_file);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10039510
PizzaMissionState::Mission* PizzaMissionState::GetMission(MxU8 p_actorId)
{
	for (MxS16 i = 0; i < 5; i++) {
		if (m_missions[i].m_actorId == p_actorId) {
			return m_missions + i;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10039540
MxS16 PizzaMissionState::FUN_10039540()
{
	return m_pizzeriaState->FUN_10017d50();
}
