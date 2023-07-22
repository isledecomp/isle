#include "mxentity.h"

// OFFSET: LEGO1 0x1001d190
MxEntity::MxEntity()
{
  this->m_mxEntityId = -1;
}

// OFFSET: LEGO1 0x1000c110
MxEntity::~MxEntity()
{
}

// OFFSET: LEGO1 0x10001070
MxResult MxEntity::SetEntityId(MxS32 p_id, MxAtomId *p_atom)
{
  this->m_mxEntityId = p_id;
  // FIXME: MxAtomId operator call, probably it will be return whatever the comparison is for comparing this->m_atom to the p_atom
  return FALSE;
}