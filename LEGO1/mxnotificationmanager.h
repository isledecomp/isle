#ifndef MXNOTIFICATIONMANAGER_H
#define MXNOTIFICATIONMANAGER_H

#include "mxcore.h"

// VTABLE 0x100dc078
class MxNotificationManager : public MxCore
{
public:
  virtual ~MxNotificationManager(); // vtable+0x0

  virtual MxLong Tickle(); // vtable+0x8

  // 0x10: MxCriticalSection
};

#endif // MXNOTIFICATIONMANAGER_H
