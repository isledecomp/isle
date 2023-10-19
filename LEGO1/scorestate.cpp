#include "scorestate.h"

// OFFSET: LEGO1 0x1000de20
MxBool ScoreState::VTable0x14() {
  return FALSE;
}

// OFFSET: LEGO1 0x1000de30
MxBool ScoreState::VTable0x18()
{
  m_unk0x08 = TRUE;
  return TRUE;
}
