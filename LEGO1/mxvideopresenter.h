#ifndef MXVIDEOPRESENTER_H
#define MXVIDEOPRESENTER_H

#include "mxmediapresenter.h"

class MxVideoPresenter : public MxMediaPresenter
{
public:
  // OFFSET: LEGO1 0x1000c820
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    // 0x100f0760
    return "MxVideoPresenter";
  }; 

  // OFFSET: LEGO1 0x1000c830
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, MxVideoPresenter::GetClassName()) || MxMediaPresenter::IsClass(name);
  };

  virtual void EndAction(); // vtable+0x40, override MxPresenter

  virtual void VTable0x18(); // vtable+0x18
  virtual void VTable0x1c(); // vtable+0x1c
  virtual void VTable0x20(); // vtable+0x20
  virtual void VTable0x24(); // vtable+0x24
  virtual void VTable0x28(); // vtable+0x28
  virtual undefined4 VTable0x34(); // vtable+0x34
  virtual void InitVirtual(); // vtable+0x38
};

#endif // MXVIDEOPRESENTER_H
