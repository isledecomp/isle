#include "legostate.h"

DECOMP_SIZE_ASSERT(LegoState, 0x08);

// OFFSET: LEGO1 0x10005f40
LegoState::~LegoState()
{
}

// OFFSET: LEGO1 0x10005f90
MxBool LegoState::VTable0x14() {
  return TRUE;
}
