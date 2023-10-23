#include "pizzamissionstate.h"

DECOMP_SIZE_ASSERT(PizzaMissionStateEntry, 0x20)
DECOMP_SIZE_ASSERT(PizzaMissionState, 0xb0)

// OFFSET: LEGO1 0x10039510
PizzaMissionStateEntry *PizzaMissionState::GetState(MxU8 id)
{
  for (MxS16 i = 0; i < 5; i++)
    if (m_state[i].m_id == id)
      return m_state + i;
  return NULL;
}