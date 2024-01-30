#include "legostate.h"

DECOMP_SIZE_ASSERT(LegoState, 0x08)
DECOMP_SIZE_ASSERT(LegoState::StateStruct, 0x0c)

// FUNCTION: LEGO1 0x10017c00
LegoState::StateStruct::StateStruct()
{
	m_unk0x04 = 0;
	m_unk0x00 = 0;
	m_unk0x06 = 0;
	m_unk0x08 = 0;
}
