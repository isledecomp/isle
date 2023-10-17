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

// OFFSET: LEGO1 0x10005fa0
MxBool LegoState::VTable0x18() {
  return FALSE;
}

// OFFSET: LEGO1 0x10005fb0
MxResult LegoState::VTable0x1C(LegoFileStream *p_legoFileStream)
{
  if (p_legoFileStream->IsWriteMode()) {
    p_legoFileStream->FUN_10006030(this->ClassName());
  }
  return SUCCESS;
}
