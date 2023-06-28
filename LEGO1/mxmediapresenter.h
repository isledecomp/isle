#ifndef MXMEDIAPRESENTER_H
#define MXMEDIAPRESENTER_H

#include "mxpresenter.h"

class MxMediaPresenter : public MxPresenter
{
public:
  virtual long Tickle(); // vtable+0x8, override MxCore

  // OFFSET: LEGO1 0x100d4ce4
  inline virtual const char *MxMediaPresenter::ClassName() const // vtable+0xc
  {
    // 0x100f074c
    return "MxMediaPresenter";
  }

  // OFFSET: LEGO1 0x1000c5d0
  inline virtual MxBool MxMediaPresenter::IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, MxMediaPresenter::ClassName()) || MxPresenter::IsA(name);
  }

  virtual void VTable0x20(); // vtable+0x20, override MxPresenter
  virtual void VTable0x24(); // vtable+0x24, override MxPresenter
  virtual void InitVirtual(); // vtable+0x38
  virtual void DoneTickle(); // vtable+0x2c, override MxPresenter
  virtual long StartAction(MxStreamController*, MxDSAction*); // vtable+0x3c, override
  virtual void EndAction(); // vtable+0x40, override MxPresenter
  virtual void Enable(unsigned char param); // vtable+0x54, override MxPresenter
  virtual void VTable0x58(undefined4 param); // vtable+0x58

  // VTABLE 0x100d4cd8
};

#endif // MXMEDIAPRESENTER_H
