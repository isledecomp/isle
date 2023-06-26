#ifndef MXWAVEPRESENTER_H
#define MXWAVEPRESENTER_H

#include "mxsoundpresenter.h"

class MxWavePresenter : public MxSoundPresenter
{
private:
  void Init();
  
public:
  virtual void VTable0x60(int param_1); // vtable+0x60
  virtual void VTable0x64(int param_1); // vtable+0x64
  virtual void VTable0x68(int param_1); // vtable+0x68

  // VTABLE 0x100d49a8
  // SIZE 0x6c
};

#endif // MXWAVEPRESENTER_H
