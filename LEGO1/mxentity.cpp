#include "mxentity.h"

DECOMP_SIZE_ASSERT(MxEntity, 0x10)

// FUNCTION: LEGO1 0x1000c110
MxEntity::~MxEntity()
{
}

// FUNCTION: LEGO1 0x1001d190
MxEntity::MxEntity()
{
	this->m_mxEntityId = -1;
}
