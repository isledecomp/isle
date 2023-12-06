#include "mxentity.h"

DECOMP_SIZE_ASSERT(MxEntity, 0x10)

// FUNCTION: LEGO1 0x10001070
MxResult MxEntity::Create(MxS32 p_id, const MxAtomId& p_atom)
{
	this->m_mxEntityId = p_id;
	this->m_atom = p_atom;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1000c110
MxEntity::~MxEntity()
{
}

// FUNCTION: LEGO1 0x1001d190
MxEntity::MxEntity()
{
	this->m_mxEntityId = -1;
}
