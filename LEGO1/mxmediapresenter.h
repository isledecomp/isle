#ifndef MXMEDIAPRESENTER_H
#define MXMEDIAPRESENTER_H

#include "mxpresenter.h"

// VTABLE 0x100d4cd8
class MxMediaPresenter : public MxPresenter
{
public:
  inline MxMediaPresenter()
  {
    Init();
  }

  virtual long Tickle() override; // vtable+0x8, override MxCore

  // OFFSET: LEGO1 0x1000c5c0
  inline virtual const char *ClassName() const override // vtable+0xc
  {
    // 0x100f074c
    return "MxMediaPresenter";
  }

  // OFFSET: LEGO1 0x1000c5d0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxMediaPresenter::ClassName()) || MxPresenter::IsA(name);
  }

private:
  void Init();

};

#endif // MXMEDIAPRESENTER_H
