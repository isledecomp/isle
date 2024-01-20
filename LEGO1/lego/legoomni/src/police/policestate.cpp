#include "policestate.h"

#include <stdlib.h>

DECOMP_SIZE_ASSERT(PoliceState, 0x10)

// FUNCTION: LEGO1 0x1005e7c0
PoliceState::PoliceState()
{
	m_unk0xc = 0;
	m_unk0x8 = (rand() % 2 == 0) ? 501 : 500;
}
