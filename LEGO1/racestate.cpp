#include "racestate.h"

// OFFSET: LEGO1 0x10015f30 STUB
RaceState::RaceState()
{
  // TODO
}

// OFFSET: LEGO1 0x10016280
RaceStateEntry *RaceState::GetState(MxU8 id)
{
  for (MxU16 i = 0; i < 5; i++) {
    if (m_state[i].m_id == id) return m_state + i;
  }
  return NULL;
}