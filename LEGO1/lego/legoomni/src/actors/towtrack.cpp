#include "towtrack.h"

#include "legogamestate.h"
#include "misc.h"
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

// STUB: LEGO1 0x1004c9e0
MxResult TowTrack::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
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
