#include "racecar.h"

DECOMP_SIZE_ASSERT(RaceCar, 0x164);

// OFFSET: LEGO1 0x10028200
RaceCar::RaceCar()
{
  this->m_unk13c = 40.0;
}

// OFFSET: LEGO1 0x10028420 STUB
RaceCar::~RaceCar()
{
  // TODO
}
