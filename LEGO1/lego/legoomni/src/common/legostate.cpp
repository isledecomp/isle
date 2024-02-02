#include "legostate.h"

DECOMP_SIZE_ASSERT(LegoState, 0x08)
DECOMP_SIZE_ASSERT(LegoState::Shuffle, 0x0c)

// STUB: LEGO1 0x10014d00
MxU32 LegoState::Shuffle::FUN_10014d00()
{
	// TODO
	return m_objectIds[0];
}

// STUB: LEGO1 0x10014de0
MxBool LegoState::Shuffle::FUN_10014de0(MxU32 p_objectId)
{
	// TODO
	return FALSE;
}
