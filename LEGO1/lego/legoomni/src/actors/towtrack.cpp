#include "towtrack.h"

#include "legogamestate.h"
#include "legovariables.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "mxvariabletable.h"
#include "towtrackmissionstate.h"

DECOMP_SIZE_ASSERT(TowTrack, 0x180)

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
	m_unk0x13c = 40.0;
	m_unk0x178 = 1.0;
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
MxU32 TowTrack::VTable0xd8(LegoEndAnimNotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1004d330
MxU32 TowTrack::VTable0xdc(MxType19NotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1004d690
MxU32 TowTrack::VTable0xcc()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x1004d8f0
void TowTrack::VTable0xe4()
{
	// TODO
}

// STUB: LEGO1 0x1004d9e0
MxU32 TowTrack::VTable0xd4(LegoControlManagerEvent& p_param)
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
