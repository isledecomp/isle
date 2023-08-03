#include "mxentity.h"

DECOMP_SIZE_ASSERT(MxEntity, 0x68)

// OFFSET: LEGO1 0x1001d190
MxEntity::MxEntity()
{
  this->m_mxEntityId = -1;
}

// OFFSET: LEGO1 0x1000c110
MxEntity::~MxEntity()
{
}
