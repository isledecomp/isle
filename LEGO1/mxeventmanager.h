#ifndef MXEVENTMANAGER_H
#define MXEVENTMANAGER_H

#include "mxmediamanager.h"
#include "decomp.h"

// VTABLE 0x100dc900
// SIZE 0x2c
class MxEventManager : public MxMediaManager
{
public:
  MxEventManager();
  virtual ~MxEventManager() override;
  virtual MxResult CreateEventThread(MxU32 p_frequencyMS, MxBool p_noRegister); // vtable+28
private:
  void Init();
};

#endif // MXEVENTMANAGER_H
