#include "islepathactor.h"

DECOMP_SIZE_ASSERT(IslePathActor, 0x160)

// OFFSET: LEGO1 0x1001a200
IslePathActor::IslePathActor()
{
  this->m_pLegoWorld = NULL;
  this->m_unk13c = 6.0;
  this->m_unk15c = 1.0;
  this->m_unk158 = 0;
}

MxResult IslePathActor::InitFromMxDSObject(MxDSObject &p_dsObject) {
  return MxEntity::InitFromMxDSObject(p_dsObject);
}