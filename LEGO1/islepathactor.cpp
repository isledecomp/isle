#include "islepathactor.h"

// OFFSET: LEGO1 0x1001a200
IslePathActor::IslePathActor()
{
  this->m_pLegoWorld = NULL;
  this->m_unk13c = 0x40c00000;
  this->m_fourcc = 0x3f800000;
  this->m_unk158 = 0;
}

// OFFSET: LEGO1 0x10002e10
IslePathActor::~IslePathActor()
{
}