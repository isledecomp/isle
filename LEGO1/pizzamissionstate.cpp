#include "pizzamissionstate.h"

// OFFSET: LEGO1 0x10039510
PizzaMissionStateEntry *PizzaMissionState::GetState(MxU8 id)
{
  for (MxU16 i = 0; i < 5; i++) {
    if (m_state[i].m_id == id) return m_state + i;
  }
  return NULL;
}