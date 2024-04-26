#include "ambulancemissionstate.h"

DECOMP_SIZE_ASSERT(AmbulanceMissionState, 0x24)

// FUNCTION: LEGO1 0x100373a0
AmbulanceMissionState::AmbulanceMissionState()
{
	m_unk0x10 = 0;
	m_unk0x12 = 0;
	m_unk0x14 = 0;
	m_unk0x08 = 0;
	m_unk0x16 = 0;
	m_unk0x0c = 0;
	m_unk0x18 = 0;
	m_score1 = 0;
	m_score2 = 0;
	m_score3 = 0;
	m_score4 = 0;
	m_score5 = 0;
}

// STUB: LEGO1 0x10037440
MxResult AmbulanceMissionState::Serialize(LegoFile* p_legoFile)
{
	// TODO
	return LegoState::Serialize(p_legoFile);
}
