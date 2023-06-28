#ifndef MXSOUNDPRESENTER_H
#define MXSOUNDPRESENTER_H

#include "mxaudiopresenter.h"

class MxSoundPresenter : public MxAudioPresenter
{
public:
  // OFFSET: LEGO1 0x1000d4a0
  inline virtual const char *ClassName() const // vtable+0x0c
  { 
    // 0x100f07a0
    return "MxSoundPresenter";
  }; 

  // OFFSET: LEGO1 0x1000d4b0
  inline virtual MxBool IsA(const char *name) const // vtable+0x10
  {
    return !strcmp(name, MxSoundPresenter::ClassName()) || MxAudioPresenter::IsA(name);
  };

  virtual undefined4 VTable0x34(); // vtable+0x34
  virtual void InitVirtual(); // vtable+0x38
};

#endif // MXSOUNDPRESENTER_H
