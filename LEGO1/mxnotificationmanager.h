#ifndef MXNOTIFICATIONMANAGER_H
#define MXNOTIFICATIONMANAGER_H

#include "mxcore.h"

class MxNotificationManager : public MxCore
{
public:
  virtual ~MxNotificationManager(); // vtable+0x0

  virtual long Tickle(); // vtable+0x8

  // 0x10: MxCriticalSection
  // VTABLE 0x100dc078
};

#endif // MXNOTIFICATIONMANAGER_H
