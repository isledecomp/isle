#include "towtrack.h"

#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legovariables.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "mxvariabletable.h"

DECOMP_SIZE_ASSERT(TowTrack, 0x180)
DECOMP_SIZE_ASSERT(TowTrackMissionState, 0x28)

// FUNCTION: LEGO1 0x1004c720
TowTrack::TowTrack()
{
	m_unk0x168 = 0;
	m_unk0x16a = -1;
	m_state = NULL;
	m_unk0x16c = 0;
	m_unk0x170 = -1;
	m_unk0x16e = 0;
	m_unk0x174 = -1;
	m_maxLinearVel = 40.0;
	m_unk0x178 = 1.0;
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
	m_unk0x178 = 1.0;
	m_time = Timer()->GetTime();
	return result;
}

// STUB: LEGO1 0x1004cb10
void TowTrack::VTable0x70(float p_float)
{
	// TODO
}

// FUNCTION: LEGO1 0x1004cc40
void TowTrack::CreateState()
{
	m_state = (TowTrackMissionState*) GameState()->GetState("TowTrackMissionState");
	if (m_state == NULL) {
		m_state = (TowTrackMissionState*) GameState()->CreateState("TowTrackMissionState");
	}
}

// STUB: LEGO1 0x1004cc80
MxLong TowTrack::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1004cd30
MxLong TowTrack::HandleEndAnim(LegoEndAnimNotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1004d330
MxLong TowTrack::HandlePathStruct(LegoPathStructEvent& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1004d690
MxLong TowTrack::HandleClick()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1004d8f0
void TowTrack::Exit()
{
	// TODO
}

// STUB: LEGO1 0x1004d9e0
MxLong TowTrack::HandleControl(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1004dab0
void TowTrack::FUN_1004dab0()
{
	// TODO
}

// STUB: LEGO1 0x1004dad0
void TowTrack::FUN_1004dad0()
{
	// TODO
}

// STUB: LEGO1 0x1004db10
void TowTrack::FUN_1004db10()
{
	// TODO
}

// STUB: LEGO1 0x1004dbe0
void TowTrack::FUN_1004dbe0()
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
	m_unk0x10 = 0;
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
		ReadFromStorage(p_file, &m_unk0x12);
		ReadFromStorage(p_file, &m_unk0x14);
		ReadFromStorage(p_file, &m_unk0x16);
		ReadFromStorage(p_file, &m_unk0x18);
		ReadFromStorage(p_file, &m_unk0x1a);
		ReadFromStorage(p_file, &m_score1);
		ReadFromStorage(p_file, &m_score2);
		ReadFromStorage(p_file, &m_score3);
		ReadFromStorage(p_file, &m_score4);
		ReadFromStorage(p_file, &m_score5);
	}
	else if (p_file->IsWriteMode()) {
		WriteToStorage(p_file, m_unk0x12);
		WriteToStorage(p_file, m_unk0x14);
		WriteToStorage(p_file, m_unk0x16);
		WriteToStorage(p_file, m_unk0x18);
		WriteToStorage(p_file, m_unk0x1a);
		WriteToStorage(p_file, m_score1);
		WriteToStorage(p_file, m_score2);
		WriteToStorage(p_file, m_score3);
		WriteToStorage(p_file, m_score4);
		WriteToStorage(p_file, m_score5);
	}

	return SUCCESS;
}
