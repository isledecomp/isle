#ifndef MXMIDIPRESENTER_H
#define MXMIDIPRESENTER_H

#include "mxmusicpresenter.h"

// VTABLE 0x100dca20
class MxMIDIPresenter : public MxMusicPresenter
{
public:
  MxMIDIPresenter();
  ~MxMIDIPresenter();

  // OFFSET: LEGO1 0x100c2650
  inline virtual const char *ClassName() const override // vtable+0xc
  {
    // 0x10101df8
    return "MxMIDIPresenter";
  }

  // OFFSET: LEGO1 0x100c2660
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxMIDIPresenter::ClassName()) || MxMusicPresenter::IsA(name);
  }

private:
  void Init();
  void Destroy(MxBool);

  undefined4 m_unk54;
};

#endif // MXMIDIPRESENTER_H
