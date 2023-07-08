#include "mxentity.h"

// OFFSET: LEGO1 0x1001d190
MxEntity::MxEntity()
{
  // FIXME: This won't match because of m_atom. How would it access m_internal?
  this->m_atom = NULL;
  this->m_mxEntityId = -1;
}

// OFFSET: LEGO1 0x1000c110
MxEntity::~MxEntity()
{
  *this->m_atom;
}