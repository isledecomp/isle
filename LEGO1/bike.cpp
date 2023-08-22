#include "bike.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(Bike, 0x164);

// OFFSET: LEGO1 0x10076670
Bike::Bike()
{
  this->m_unk13c = 20.0;
  this->m_unk150 = 3.0;
  this->m_unk148 = 1;
}

