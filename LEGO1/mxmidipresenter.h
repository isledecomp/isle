#ifndef MXMIDIPRESENTER_H
#define MXMIDIPRESENTER_H

#include "mxmusicpresenter.h"

// VTABLE 0x100dca20
class MxMIDIPresenter : public MxMusicPresenter
{
public:
  MxMIDIPresenter();
private:
  void Init();
  undefined4 m_unk54;
};

#endif // MXMIDIPRESENTER_H
