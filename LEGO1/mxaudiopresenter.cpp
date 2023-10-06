#include "mxaudiopresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxAudioPresenter, 0x54);

// OFFSET: LEGO1 0x1000d260
undefined4 MxAudioPresenter::vtable5c()
{
  return this->m_unk50;
}

// OFFSET: LEGO1 0x1000d270
void MxAudioPresenter::vtable60(undefined4 p_unk50)
{
  this->m_unk50 = p_unk50;
}
