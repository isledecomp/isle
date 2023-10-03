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
  Destroy(TRUE);
}

// OFFSET: LEGO1 0x100b4410
void MxLoopingFlcPresenter::Init()
{
  this->m_unk68 = 0;
  this->m_flags &= 0xfd;
  this->m_flags &= 0xfb;
}

// OFFSET: LEGO1 0x100b4432 STUB
void MxLoopingFlcPresenter::Destroy(MxBool p_param)
{
  // TODO 
}
