#include "mxmidipresenter.h"

#include "decomp.h"

DECOMP_STATIC_ASSERT(sizeof(MxMIDIPresenter) == 88);

// OFFSET: LEGO1 0x100c25e0
MxMIDIPresenter::MxMIDIPresenter() {
  Init();
}

// OFFSET: LEGO1 0x100c2820
void MxMIDIPresenter::Init()
{
  m_unk54 = 0;
}
