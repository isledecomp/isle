#include "pizzamissionstate.h"

DECOMP_SIZE_ASSERT(PizzaMissionStateEntry, 0x20)
DECOMP_SIZE_ASSERT(PizzaMissionState, 0xb0)

// STUB: LEGO1 0x100393c0
MxResult PizzaMissionState::VTable0x1c(LegoFileStream* p_legoFileStream)
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10039510
PizzaMissionStateEntry* PizzaMissionState::GetState(MxU8 p_id)
{
	for (MxS16 i = 0; i < 5; i++)
		if (m_state[i].m_id == p_id)
			return m_state + i;
	return NULL;
}
