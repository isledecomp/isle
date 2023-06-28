#ifndef MXAUDIOPRESENTER_H
#define MXAUDIOPRESENTER_H

#include "mxmediapresenter.h"

class MxAudioPresenter : public MxMediaPresenter
{
public:
  // OFFSET: LEGO1 0x1000d280
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    // 0x100f078c
    return "MxAudioPresenter";
  }; 

  // OFFSET: LEGO1 0x1000d290
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, MxAudioPresenter::ClassName()) || MxMediaPresenter::IsA(name);
  };

  virtual undefined4 VTable0x5c(); // vtable+0x5c
  virtual void VTable0x60(undefined4 param); // vtable+0x60
};

#endif // MXAUDIOPRESENTER_H
