#ifndef LEGOINPUTMANAGER_H
#define LEGOINPUTMANAGER_H

#include "decomp.h"
#include "mxpresenter.h"
#include "legocontrolmanager.h"
#include <dinput.h>

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
  void Destroy();
  MxS32 GetJoystickState(unsigned int* something_x, unsigned int* something_y, DWORD* buttons_state, unsigned int* pov_position);
  void CreateAndAcquireKeyboard(HWND hwnd);
  MxS32 GetJoystickId();
  void ReleaseDX();
  void SetTimer();
  void KillTimer();

  //virtual MxLong Tickle() override; // vtable+0x8
  MxCriticalSection m_criticalsection;                // 0x40
  MxS32 m_unknown5C;                                  // 0x5C
  MxS32* m_unknown60;                                 // 0x60
  MxS32* m_unknown64;                                 // 0x64
  void* m_unknown_classptr68;                         // 0x68
  MxS32 m_unknown6C;                                  // 0x6C
  MxS32 m_unknown70;                                  // 0x70
  MxS32 m_unknown74;                                  // 0x74
  UINT m_timer;                                       // 0x78
  UINT m_timeout;                                     // 0x7C
  MxU8 m_unknown80;                                   // 0x80
  MxBool m_bool81;                                    // 0x81
  MxU8 m_unknown82;                                   // 0x82
  MxU8 m_unknown83;                                   // 0x83
  LegoControlManager* m_controlManager;               // 0x84
  MxBool m_bool88;                                    // 0x88
  MxU8 m_unknown89[3];                                // 0x89
  IDirectInputA* m_directinputInterface;              // 0x8C
  IDirectInputDeviceA* m_directinputDeviceInterface;  // 0x90
  MxU8 m_unused94;                                    // 0x94
  MxU8 m_unknown95[3];                                // 0x95
  void* m_unknown98;                                  // 0x98
  MxU8 m_unknown9C[0xF8];                             // 0x9C
  MxBool m_unknown195;                                // 0x195
  MxU8 m_unknown196[2];                               // 0x196
  UINT m_joyid;                                       // 0x198
  UINT m_unknown19C;                                  // 0x19C
  JOYCAPSA m_joyCapsA;                                // 0x1a0
  MxU8 m_joystickIndex;                               // 0x334
  MxBool m_useJoystick;                               // 0x335
  MxU8 m_unknown336;                                  // 0x336
  MxU8 m_unknown337;                                  // 0x337
  MxU8 m_unknown338;                                  // 0x338
};

#endif // LEGOINPUTMANAGER_H
