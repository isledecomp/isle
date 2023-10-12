#include "motorcycle.h"

DECOMP_SIZE_ASSERT(Motorcycle, 0x16c);

// OFFSET: LEGO1 0x100357b0
Motorcycle::Motorcycle()
{
  this->m_unk13c = 40.0;
  this->m_unk150 = 1.75;
  this->m_unk148 = 1;
  this->m_unk164 = 1.0;
}
