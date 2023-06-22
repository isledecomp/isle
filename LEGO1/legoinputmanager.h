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
  __declspec(dllexport) void QueueEvent(NotificationId id, unsigned char p2, long p3, long p4, unsigned char p5);
  __declspec(dllexport) void Register(MxCore *);
  __declspec(dllexport) void UnRegister(MxCore *);

  char m_pad00[0x19C];
  int m_joystickIndex;
  char m_pad200[0x194];
  MxBool m_useJoystick;
};

#endif // LEGOINPUTMANAGER_H
