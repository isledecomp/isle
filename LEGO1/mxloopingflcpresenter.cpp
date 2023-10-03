#include "mxloopingflcpresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxLoopingFlcPresenter, 0x6c);

// OFFSET: LEGO1 0x100b4310
MxLoopingFlcPresenter::MxLoopingFlcPresenter()
{
  Init();
}

// OFFSET: LEGO1 0x100b43b0 STUB
MxLoopingFlcPresenter::~MxLoopingFlcPresenter()
{
  // TODO
}

// OFFSET: LEGO1 0x100b4410
void MxLoopingFlcPresenter::Init()
{
  this->m_unk68 = 0;
}
