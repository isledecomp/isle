#ifndef LEGOINPUTMANAGER_H
#define LEGOINPUTMANAGER_H

#include "decomp.h"
#include "mxpresenter.h"

enum NotificationId
{
  NONE = 0,
  KEYDOWN = 7,
  MOUSEUP = 8,
  MOUSEDOWN = 9,
  MOUSEMOVE = 10,
  TIMER = 15
};

// VTABLE 0x100d8760
// SIZE 0x338
class LegoInputManager : public MxPresenter
{
public:
  LegoInputManager();
  virtual ~LegoInputManager() override;

  __declspec(dllexport) void QueueEvent(NotificationId id, unsigned char p2, MxLong p3, MxLong p4, unsigned char p5);
  __declspec(dllexport) void Register(MxCore *);
  __declspec(dllexport) void UnRegister(MxCore *);

  virtual MxResult Tickle() override; // vtable+0x8

  undefined m_pad40[0x48];

  MxBool m_unk88;
  MxU8 m_unk89;
  MxU8 m_unk8a;
  MxU8 m_unk8b;

  undefined m_pad8c[0x110];

  // 0x19C
  int m_joystickIndex;

  undefined m_pad1a0[0x194];

  // 0x334
  MxBool m_useJoystick;

  MxU8 m_unk335;
  MxBool m_unk336;
  MxU8 m_unk337;
};

#endif // LEGOINPUTMANAGER_H
