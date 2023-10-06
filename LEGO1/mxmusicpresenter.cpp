#include "mxmusicpresenter.h"

// OFFSET: LEGO1 0x100c22c0
MxMusicPresenter::MxMusicPresenter()
{
  Init();
}

// OFFSET: LEGO1 0x100c24e0
MxMusicPresenter::~MxMusicPresenter()
{
  Destroy(TRUE);
}

// OFFSET: LEGO1 0x100c2540
void MxMusicPresenter::Init()
{
}

// OFFSET: LEGO1 0x100c2550 STUB
void MxMusicPresenter::Destroy(MxBool)
{
  // TODO
}