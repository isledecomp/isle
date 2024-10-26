#include "pizza.h"

#include "isle.h"
#include "isle_actions.h"
#include "jukebox_actions.h"
#include "legoanimationmanager.h"
#include "legogamestate.h"
#include "legoutils.h"
#include "legoworld.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "pizzeria.h"
#include "skateboard.h"

DECOMP_SIZE_ASSERT(Pizza, 0x9c)
DECOMP_SIZE_ASSERT(PizzaMissionState, 0xb4)
DECOMP_SIZE_ASSERT(PizzaMissionState::Mission, 0x20)

// Flags used in isle.cpp
extern MxU32 g_isleFlags;

// FUNCTION: LEGO1 0x10037ef0
Pizza::Pizza()
{
	m_state = NULL;
	m_mission = NULL;
	m_skateBoard = NULL;
	m_act1state = NULL;
	m_unk0x8c = -1;
	m_unk0x98 = 0;
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
void Pizza::FUN_10038220(MxU32 p_objectId)
{
	AnimationManager()->FUN_10064740(NULL);
	m_mission = m_state->GetState(GameState()->GetActorId());
	m_state->m_unk0x0c = 1;
	m_act1state->m_unk0x018 = 3;
	m_mission->m_startTime = INT_MIN;
	g_isleFlags &= ~Isle::c_playMusic;
	AnimationManager()->EnableCamAnims(FALSE);
	AnimationManager()->FUN_1005f6d0(FALSE);
	FUN_10038fe0(p_objectId, FALSE);
	m_unk0x8c = -1;
}

// FUNCTION: LEGO1 0x100382b0
void Pizza::FUN_100382b0()
{
	if (m_state->m_unk0x0c != 8) {
		if (m_unk0x8c != -1) {
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
		m_unk0x98 = 0;
		m_unk0x8c = -1;
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

		FUN_10038fe0(action, TRUE);
		m_state->m_unk0x0c = 3;
		PlayMusic(JukeboxScript::c_PizzaMission_Music);
		return 1;
	}

	return 0;
}

// STUB: LEGO1 0x100384f0
MxLong Pizza::HandlePathStruct(LegoPathStructNotificationParam&)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100388a0
MxResult Pizza::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10038b10
MxLong Pizza::HandleEndAction(MxEndActionNotificationParam&)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10038fe0
void Pizza::FUN_10038fe0(MxU32 p_objectId, MxBool)
{
	// TODO
}

// STUB: LEGO1 0x10039030
PizzaMissionState::PizzaMissionState()
{
	// TODO
}

// FUNCTION: LEGO1 0x100393c0
MxResult PizzaMissionState::Serialize(LegoFile* p_file)
{
	LegoState::Serialize(p_file);

	if (p_file->IsReadMode()) {
		for (MxS16 i = 0; i < 5; i++) {
			m_state[i].ReadFromFile(p_file);
		}
	}
	else if (p_file->IsWriteMode()) {
		for (MxS16 i = 0; i < 5; i++) {
			m_state[i].WriteToFile(p_file);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10039510
PizzaMissionState::Mission* PizzaMissionState::GetState(MxU8 p_id)
{
	for (MxS16 i = 0; i < 5; i++) {
		if (m_state[i].m_id == p_id) {
			return m_state + i;
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10039540
MxS16 PizzaMissionState::FUN_10039540()
{
	return m_pizzeriaState->FUN_10017d50();
}
