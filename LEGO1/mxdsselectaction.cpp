#include "mxdsselectaction.h"

DECOMP_SIZE_ASSERT(MxDSSelectAction, 0xb0)

// OFFSET: LEGO1 0x100cb2b0
MxDSSelectAction::MxDSSelectAction()
{
  this->SetType(MxDSType_SelectAction);
  this->m_unk0xac = new MxStringList;
}

// OFFSET: LEGO1 0x100cb8d0
MxDSSelectAction::~MxDSSelectAction()
{
  if (this->m_unk0xac)
    delete this->m_unk0xac;
}
