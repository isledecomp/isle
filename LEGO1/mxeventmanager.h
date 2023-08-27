#ifndef MXEVENTMANAGER_H
#define MXEVENTMANAGER_H

#include "mxmediamanager.h"

// VTABLE 0x100dc900
// SIZE 0x2c
class MxEventManager : public MxMediaManager
{
public:
  MxEventManager();
  virtual ~MxEventManager() override;

private:
  void Init();
};

#endif // MXEVENTMANAGER_H
