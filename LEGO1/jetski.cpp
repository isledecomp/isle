#include "jetski.h"

DECOMP_SIZE_ASSERT(Jetski, 0x164);

// OFFSET: LEGO1 0x1007e3b0
Jetski::Jetski()
{
  this->m_unk13c = 25.0;
  this->m_unk150 = 2.0;
  this->m_unk148 = 1;
}