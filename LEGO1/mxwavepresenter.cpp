#include "mxwavepresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxWavePresenter, 0x6c);

// OFFSET: LEGO1 0x100b1ad0
void MxWavePresenter::Init()
{
  m_unk54 = 0;
  m_unk58 = 0;
  m_unk5c = 0;
  m_unk60 = 0;
  m_unk64 = 0;
  m_unk65 = 0;
  m_unk66 = 0;
  m_unk68 = 0;
}
