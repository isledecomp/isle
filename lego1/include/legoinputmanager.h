#ifndef LEGOINPUTMANAGER_H
#define LEGOINPUTMANAGER_H

__declspec(dllexport) enum NotificationId
{
  NONE = 0x0,
  KEYDOWN = 0x7,
  MOUSEUP = 0x8,
  MOUSEDOWN = 0x9,
  MOUSEMOVE = 0x10,
  TIMER = 0xF
};

class LegoInputManager
{
public:
  __declspec(dllexport) void QueueEvent(NotificationId id, unsigned char p2, long p3, long p4, unsigned char p5);
  __declspec(dllexport) void Register(MxCore *);
  __declspec(dllexport) void UnRegister(MxCore *);

  int m_unk00[0x400];
};

#endif // LEGOINPUTMANAGER_H
