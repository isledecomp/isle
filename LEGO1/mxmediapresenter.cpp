#include "mxmediapresenter.h"

DECOMP_SIZE_ASSERT(MxMediaPresenter, 0x50);

// OFFSET: LEGO1 0x100b5d10 STUB
MxLong MxMediaPresenter::Tickle()
{
  // TODO
  return 0;
}

// OFFSET: LEGO1 0x100b54e0
void MxMediaPresenter::Init()
{
  this->m_unk40 = NULL;
  this->m_unk44 = NULL;
  this->m_unk48 = NULL;
  this->m_unk4c = NULL;
}
