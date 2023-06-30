#include "mxeventpresenter.h"

#include "decomp.h"

DECOMP_STATIC_ASSERT(sizeof(MxEventPresenter) == 84);

// OFFSET: LEGO1 0x100c2b70
MxEventPresenter::MxEventPresenter()
{
  Init();
}

// OFFSET: LEGO1 0x100c2d40 STUB
MxEventPresenter::~MxEventPresenter()
{
  // TODO
}

// OFFSET: LEGO1 0x100c2da0
void MxEventPresenter::Init()
{
  m_unk50 = 0;
}
