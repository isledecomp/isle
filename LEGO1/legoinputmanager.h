#ifndef LEGOINPUTMANAGER_H
#define LEGOINPUTMANAGER_H

#include "mxcore.h"

__declspec(dllexport) enum NotificationId
{
  NONE = 0,
  KEYDOWN = 7,
  MOUSEUP = 8,
  MOUSEDOWN = 9,
  MOUSEMOVE = 10,
  TIMER = 15
};

class LegoInputManager
{
public:
  virtual ~LegoInputManager();

  __declspec(dllexport) void QueueEvent(NotificationId id, unsigned char p2, long p3, long p4, unsigned char p5);
  __declspec(dllexport) void Register(MxCore *);
  __declspec(dllexport) void UnRegister(MxCore *);

  virtual long Tickle(); // vtable+0x8

  virtual void VTable0x38(); // vtable0x38

  int m_unk00[0x400];
};

#endif // LEGOINPUTMANAGER_H
