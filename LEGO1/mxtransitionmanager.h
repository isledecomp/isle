#ifndef MXTRANSITIONMANAGER_H
#define MXTRANSITIONMANAGER_H

class MxVideoPresenter;

class MxTransitionManager
{
public:
  __declspec(dllexport) void SetWaitIndicator(MxVideoPresenter *videoPresenter);

  virtual int DispatchTransition();
  virtual int FUN_1004baa0(); // Return is unknown 4-byte value
};

#endif // MXTRANSITIONMANAGER_H
