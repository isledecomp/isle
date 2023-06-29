#ifndef MXTRANSITIONMANAGER_H
#define MXTRANSITIONMANAGER_H

#include "mxcore.h"

class MxVideoPresenter;

// 0x100d7ea0
class MxTransitionManager : public MxCore
{
public:
  virtual ~MxTransitionManager(); // vtable+0x0

  __declspec(dllexport) void SetWaitIndicator(MxVideoPresenter *videoPresenter);

  virtual long Tickle(); // vtable+0x8
};

#endif // MXTRANSITIONMANAGER_H
