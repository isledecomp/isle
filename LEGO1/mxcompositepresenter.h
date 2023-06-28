#ifndef MXCOMPOSITEPRESENTER_H
#define MXCOMPOSITEPRESENTER_H

#include "mxpresenter.h"

class MxCompositePresenter : public MxPresenter
{
public:
  MxCompositePresenter();
  virtual ~MxCompositePresenter(); // vtable+0x0

  virtual long Notify(MxParam &p); // vtable+0x4, MxCore override

  // OFFSET: LEGO1 0x100b6210
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    // 0x100f0774
    return "MxCompositePresenter";
  }; 

  // OFFSET: LEGO1 0x100b6220
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, MxCompositePresenter::ClassName()) || MxPresenter::IsA(name);
  };

  virtual long StartAction(MxStreamController *, MxDSAction *); // vtable+0x3c
  virtual void EndAction(); // vtable+0x40
  virtual void VTable0x44(undefined4 param); // vtable+0x44
  virtual undefined4 VTable0x48(undefined4 param); // vtable+0x48
  virtual void Enable(unsigned char); // vtable+0x54
  virtual void VTable0x58(undefined4 param); // vtable+0x58
  virtual void VTable0x5c(undefined4 param); // vtable+0x5c
  virtual void VTable0x60(undefined4 param); // vtable+0x60
  virtual undefined4 VTable0x64(undefined4 param); // vtable+0x64

  // VTABLE 0x100dc618
};

#endif // MXCOMPOSITEPRESENTER_H
