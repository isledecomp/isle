#ifndef MXMEDIAPRESENTER_H
#define MXMEDIAPRESENTER_H

#include "mxpresenter.h"

class MxMediaPresenter : public MxPresenter
{
public:
  virtual long Tickle(); // vtable+0x8, override MxCore
  virtual const char *GetClassName() const; // vtable+0xc, override MxCore
  virtual MxBool IsClass(const char *name) const; // vtable+0x10, override MxCore

  virtual void VTable0x20(); // vtable+0x20, override MxPresenter
  virtual unsigned int VTable0x24(); // vtable+0x24, override MxPresenter
  virtual void DoneTickle(); // vtable+0x2c, override MxPresenter
  virtual long StartAction(MxStreamController*, MxDSAction*); // vtable+0x3c, override
  virtual void EndAction(); // vtable+0x40, override MxPresenter
  virtual void Enable(unsigned char param); // vtable+0x54, override MxPresenter

  // VTABLE 0x100d4cd8
};

#endif // MXMEDIAPRESENTER_H
