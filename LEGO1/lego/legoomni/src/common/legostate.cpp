#include "legostate.h"

DECOMP_SIZE_ASSERT(LegoState, 0x08)
DECOMP_SIZE_ASSERT(LegoState::StateStruct, 0x0c)

// STUB: LEGO1 0x10014d00
MxU32 LegoState::StateStruct::FUN_10014d00()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10014de0
MxBool LegoState::StateStruct::FUN_10014de0(MxU32 p_objectId)
{
	// TODO
	return FALSE;
}

// FUNCTION: LEGO1 0x10017c00
LegoState::StateStruct::StateStruct()
{
	m_unk0x04 = 0;
	m_unk0x00 = 0;
	m_unk0x06 = 0;
	m_unk0x08 = 0;
}
