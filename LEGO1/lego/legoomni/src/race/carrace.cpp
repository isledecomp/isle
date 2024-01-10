#include "carrace.h"

DECOMP_SIZE_ASSERT(CarRace, 0x154);

// FUNCTION: LEGO1 0x10016a90
CarRace::CarRace()
{
	this->m_unk0x150 = 0;
	this->m_unk0x130 = MxRect32(0x16c, 0x154, 0x1ec, 0x15e);
}
