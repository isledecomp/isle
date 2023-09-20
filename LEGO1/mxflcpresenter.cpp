#include "mxflcpresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxFlcPresenter, 0x68);

// OFFSET: LEGO1 0x100b3310
MxFlcPresenter::MxFlcPresenter()
{
  this->m_unk64 = 0;
  this->m_flags &= 0xfd;
  this->m_flags &= 0xfb;
}

// OFFSET: LEGO1 0x100b3420
MxFlcPresenter::~MxFlcPresenter()
{
  if (this->m_unk64) {
    delete this->m_unk64;
  }
}
