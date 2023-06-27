#ifndef MXSOUNDPRESENTER_H
#define MXSOUNDPRESENTER_H

#include "mxaudiopresenter.h"

class MxSoundPresenter : public MxAudioPresenter
{
public:
  // OFFSET: LEGO1 0x1000d4a0
  inline virtual const char *GetClassName() const // vtable+0x0c
  { 
    // 0x100f07a0
    return "MxSoundPresenter";
  }; 

  // OFFSET: LEGO1 0x1000d4b0
  inline virtual MxBool IsClass(const char *name) const // vtable+0x10
  {
    return !strcmp(name, MxSoundPresenter::GetClassName()) || MxAudioPresenter::IsClass(name);
  };

  virtual undefined4 VTable0x34(); // vtable+0x34
  virtual void InitVirtual(); // vtable+0x38
};

#endif // MXSOUNDPRESENTER_H
