#ifndef MXWAVEPRESENTER_H
#define MXWAVEPRESENTER_H

#include "mxsoundpresenter.h"

class MxWavePresenter : public MxSoundPresenter
{
private:
  void Init();
  
  virtual void FUN_100b2300(int param_1);
  virtual void FUN_100b2440(int param_1);
  virtual void FUN_100b2470(int param_1);
  // SIZE 0x6c
};

#endif // MXWAVEPRESENTER_H
