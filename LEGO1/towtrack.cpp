#include "towtrack.h"

DECOMP_SIZE_ASSERT(TowTrack, 0x180);

// OFFSET: LEGO1 0x1004c720
TowTrack::TowTrack()
{
  this->m_unk168 = 0;
  this->m_unk16a = -1;
  this->m_unk164 = 0;
  this->m_unk16c = 0;
  this->m_unk170 = -1;
  this->m_unk16e = 0;
  this->m_unk174 = -1;
  this->m_unk13c = 40.0;
  this->m_unk178 = 1.0;
}
