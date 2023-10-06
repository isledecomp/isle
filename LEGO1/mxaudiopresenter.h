#ifndef MXAUDIOPRESENTER_H
#define MXAUDIOPRESENTER_H

#include "decomp.h"
#include "mxmediapresenter.h"

// VTABLE 0x100d4c70
class MxAudioPresenter : public MxMediaPresenter
{
public:
  MxAudioPresenter() {
    m_unk50 = 100;
  }

  // OFFSET: LEGO1 0x1000d280
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x100f078c
    return "MxAudioPresenter";
  }

  // OFFSET: LEGO1 0x1000d290
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxAudioPresenter::ClassName()) || MxMediaPresenter::IsA(name);
  }

  virtual undefined4 vtable5c();
  virtual void vtable60(undefined4);

  undefined4 m_unk50;
};

#endif // MXAUDIOPRESENTER_H
