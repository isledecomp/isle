#include "gasstationstate.h"

DECOMP_SIZE_ASSERT(GasStationState, 0x24);

// FUNCTION: LEGO1 0x10005eb0
GasStationState::GasStationState()
{
	m_unk0x18 = 0;
	m_unk0x1a = 0;
	m_unk0x1c = 0;
	m_unk0x1e = 0;
	m_unk0x20 = 0;

	undefined4* unk = m_unk0x08;
	unk[0] = -1;
	unk[1] = -1;
	unk[2] = -1;
}
