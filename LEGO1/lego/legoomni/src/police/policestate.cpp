#include "policestate.h"

#include <legoutil.h> // for rand()

DECOMP_SIZE_ASSERT(PoliceState, 0x10)

// FUNCTION: LEGO1 0x1005e7c0
PoliceState::PoliceState()
{
	this->m_unk0xc = 0;
	this->m_unk0x8 = (rand() % 2 == 0) ? 501 : 500;
}
