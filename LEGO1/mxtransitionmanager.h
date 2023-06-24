#ifndef MXTRANSITIONMANAGER_H
#define MXTRANSITIONMANAGER_H

class MxVideoPresenter;

class MxTransitionManager
{
public:
  __declspec(dllexport) void SetWaitIndicator(MxVideoPresenter *videoPresenter);
  const char* GetClassName();
};

#endif // MXTRANSITIONMANAGER_H
