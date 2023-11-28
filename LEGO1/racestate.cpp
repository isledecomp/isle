#include "racestate.h"

DECOMP_SIZE_ASSERT(RaceStateEntry, 0x06)

// TODO: Must be 0x2c but current structure is incorrect
// DECOMP_SIZE_ASSERT(RaceState, 0x2c)

// FUNCTION: LEGO1 0x10015f30 STUB
RaceState::RaceState()
{
	// TODO
}

// FUNCTION: LEGO1 0x10016280
RaceStateEntry* RaceState::GetState(MxU8 id)
{
	for (MxS16 i = 0;; i++) {
		if (i >= 5)
			return NULL;
		if (m_state[i].m_id == id)
			return m_state + i;
	}
}
