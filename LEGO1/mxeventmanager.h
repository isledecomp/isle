#ifndef MXEVENTMANAGER_H
#define MXEVENTMANAGER_H
#include "decomp.h"
#include "mxmediamanager.h"

// VTABLE 0x100dc900
// SIZE 0x2c
class MxEventManager : public MxMediaManager
{
public:
  MxEventManager();
  virtual ~MxEventManager() override;
  virtual MxResult vtable0x28(undefined4 p_unknown1, MxU8 p_unknown2); // vtable+28

private:
  void Init();
};

#endif // MXEVENTMANAGER_H
