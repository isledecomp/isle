#include "mxmidipresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxMIDIPresenter, 0x58);

// OFFSET: LEGO1 0x100c25e0
MxMIDIPresenter::MxMIDIPresenter() {
  Init();
}

// OFFSET: LEGO1 0x100c27c0
MxMIDIPresenter::~MxMIDIPresenter()
{
  Destroy(TRUE);
}

// OFFSET: LEGO1 0x100c2820
void MxMIDIPresenter::Init()
{
  m_unk54 = 0;
}

// OFFSET: LEGO1 0x100c2830 STUB
void MxMIDIPresenter::Destroy(MxBool p_param)
{
  // TODO
}
