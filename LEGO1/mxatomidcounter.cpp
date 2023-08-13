#include "mxatomidcounter.h"

// OFFSET: LEGO1 0x100ad7f0
void MxAtomIdCounter::Inc()
{
  m_value++;
}

// OFFSET: LEGO1 0x100ad800
void MxAtomIdCounter::Dec()
{
  if (m_value)
    m_value--;
}
