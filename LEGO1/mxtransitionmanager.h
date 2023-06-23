#ifndef MXTRANSITIONMANAGER_H
#define MXTRANSITIONMANAGER_H

#include "mxcore.h"

class MxVideoPresenter;

#ifndef undefined4
#define undefined4 int
#endif

class MxTransitionManager : public MxCore
{
public:
  __declspec(dllexport) void SetWaitIndicator(MxVideoPresenter *videoPresenter);

  virtual long Tickle(); // vtable+0x8
  virtual undefined4 VTable0x14(); // vtable+0x14

  // VTABLE 0x100d7ea0
};

#endif // MXTRANSITIONMANAGER_H
