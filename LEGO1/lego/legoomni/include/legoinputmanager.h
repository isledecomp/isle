#ifndef LEGOINPUTMANAGER_H
#define LEGOINPUTMANAGER_H

#include "decomp.h"
#include "legoeventnotificationparam.h"
#include "legoworld.h"
#include "mxlist.h"
#include "mxpresenter.h"
#include "mxqueue.h"

#include <dinput.h>

class LegoControlManager;

extern MxS32 g_unk0x100f31b0;
extern const char* g_unk0x100f31b4;

// VTABLE: LEGO1 0x100d87b8
// class MxCollection<LegoEventNotificationParam>

// VTABLE: LEGO1 0x100d87d0
// class MxList<LegoEventNotificationParam>

// VTABLE: LEGO1 0x100d87e8
// class MxQueue<LegoEventNotificationParam>

// VTABLE: LEGO1 0x100d8800
// SIZE 0x18
class LegoEventQueue : public MxQueue<LegoEventNotificationParam> {};

// VTABLE: LEGO1 0x100d6a20
// class MxCollection<MxCore*>

// VTABLE: LEGO1 0x100d6a38
// class MxList<MxCore*>

// VTABLE: LEGO1 0x100d6a50
// class MxPtrList<MxCore>

// VTABLE: LEGO1 0x100d6a68
// SIZE 0x18
class LegoNotifyList : public MxPtrList<MxCore> {
protected:
	// FUNCTION: LEGO1 0x10028830
	MxS8 Compare(MxCore* p_element1, MxCore* p_element2) override
	{
		return p_element1 == p_element2 ? 0 : p_element1 < p_element2 ? -1 : 1;
	} // vtable+0x14

public:
	LegoNotifyList(MxBool p_ownership = FALSE) : MxPtrList<MxCore>(p_ownership) {}
};

// VTABLE: LEGO1 0x100d6ac0
// class MxListCursor<MxCore *>

// VTABLE: LEGO1 0x100d6ad8
// class MxPtrListCursor<MxCore>

// VTABLE: LEGO1 0x100d6aa8
// SIZE 0x10
class LegoNotifyListCursor : public MxPtrListCursor<MxCore> {
public:
	LegoNotifyListCursor(LegoNotifyList* p_list) : MxPtrListCursor<MxCore>(p_list) {}
};

// VTABLE: LEGO1 0x100d8760
// SIZE 0x338
class LegoInputManager : public MxPresenter {
public:
	LegoInputManager();
	~LegoInputManager() override;

	void QueueEvent(NotificationId p_id, MxU8 p_modifier, MxLong p_x, MxLong p_y, MxU8 p_key);
	void Register(MxCore*);
	void UnRegister(MxCore*);

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x1005b8c0
	MxResult PutData() override { return SUCCESS; } // vtable+0x4c

	MxResult Create(HWND p_hwnd);
	void Destroy() override;
	void CreateAndAcquireKeyboard(HWND p_hwnd);
	void ReleaseDX();
	MxResult GetJoystickId();
	MxResult GetJoystickState(MxU32* p_joystickX, MxU32* p_joystickY, DWORD* p_buttonsState, MxU32* p_povPosition);
	void StartAutoDragTimer();
	void StopAutoDragTimer();
	void EnableInputProcessing();
	void SetCamera(LegoCameraController* p_camera);
	void ClearCamera();
	void SetWorld(LegoWorld* p_world);
	void ClearWorld();

	inline void SetUnknown88(MxBool p_unk0x88) { m_unk0x88 = p_unk0x88; }
	inline void SetUnknown335(MxBool p_unk0x335) { m_unk0x335 = p_unk0x335; }
	inline void SetUnknown336(MxBool p_unk0x336) { m_unk0x336 = p_unk0x336; }
	inline void SetUseJoystick(MxBool p_useJoystick) { m_useJoystick = p_useJoystick; }
	inline void SetJoystickIndex(MxS32 p_joystickIndex) { m_joystickIndex = p_joystickIndex; }

	inline void DisableInputProcessing()
	{
		m_unk0x88 = TRUE;
		m_unk0x336 = FALSE;
	}

	inline LegoControlManager* GetControlManager() { return m_controlManager; }
	inline LegoWorld* GetWorld() { return m_world; }
	inline LegoCameraController* GetCamera() { return m_camera; }

	void ProcessEvents();
	MxBool ProcessOneEvent(LegoEventNotificationParam& p_param);
	MxBool FUN_1005cdf0(LegoEventNotificationParam& p_param);

	// SYNTHETIC: LEGO1 0x1005b8d0
	// LegoInputManager::`scalar deleting destructor'

private:
	MxCriticalSection m_criticalSection;     // 0x58
	LegoNotifyList* m_keyboardNotifyList;    // 0x5c
	LegoCameraController* m_camera;          // 0x60
	LegoWorld* m_world;                      // 0x64
	LegoEventQueue* m_eventQueue;            // 0x68
	undefined4 m_unk0x6c;                    // 0x6c
	undefined4 m_unk0x70;                    // 0x70
	undefined4 m_unk0x74;                    // 0x74
	UINT m_autoDragTimerID;                  // 0x78
	UINT m_autoDragTime;                     // 0x7c
	undefined m_unk0x80;                     // 0x80
	undefined m_unk0x81;                     // 0x81
	LegoControlManager* m_controlManager;    // 0x84
	MxBool m_unk0x88;                        // 0x88
	IDirectInput* m_directInput;             // 0x8c
	IDirectInputDevice* m_directInputDevice; // 0x90
	undefined m_unk0x94;                     // 0x94
	undefined4 m_unk0x98;                    // 0x98
	undefined m_unk0x9c[0xf8];               // 0x9c
	undefined m_unk0x194;                    // 0x194
	MxBool m_unk0x195;                       // 0x195
	MxS32 m_joyid;                           // 0x198
	MxS32 m_joystickIndex;                   // 0x19c
	JOYCAPS m_joyCaps;                       // 0x200
	MxBool m_useJoystick;                    // 0x334
	MxBool m_unk0x335;                       // 0x335
	MxBool m_unk0x336;                       // 0x336
};

// TEMPLATE: LEGO1 0x10028850
// MxCollection<MxCore *>::Compare

// TEMPLATE: LEGO1 0x10028860
// MxCollection<MxCore *>::~MxCollection<MxCore *>

// TEMPLATE: LEGO1 0x100288b0
// MxCollection<MxCore *>::Destroy

// TEMPLATE: LEGO1 0x100288c0
// MxList<MxCore *>::~MxList<MxCore *>

// SYNTHETIC: LEGO1 0x10028950
// LegoNotifyList::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100289c0
// MxPtrList<MxCore>::~MxPtrList<MxCore>

// SYNTHETIC: LEGO1 0x10028a10
// MxCollection<MxCore *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10028a80
// MxList<MxCore *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10028b30
// MxPtrList<MxCore>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x10028ba0
// LegoNotifyList::~LegoNotifyList

// SYNTHETIC: LEGO1 0x10028fd0
// LegoNotifyListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x10029040
// MxPtrListCursor<MxCore>::~MxPtrListCursor<MxCore>

// SYNTHETIC: LEGO1 0x10029090
// MxListCursor<MxCore *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10029100
// MxPtrListCursor<MxCore>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x10029170
// MxListCursor<MxCore *>::~MxListCursor<MxCore *>

// TEMPLATE: LEGO1 0x100291c0
// LegoNotifyListCursor::~LegoNotifyListCursor

// TEMPLATE: LEGO1 0x1005bb80
// MxCollection<LegoEventNotificationParam>::Compare

// TEMPLATE: LEGO1 0x1005bbe0
// MxCollection<LegoEventNotificationParam>::~MxCollection<LegoEventNotificationParam>

// TEMPLATE: LEGO1 0x1005bc30
// MxCollection<LegoEventNotificationParam>::Destroy

// TEMPLATE: LEGO1 0x1005bc80
// MxList<LegoEventNotificationParam>::~MxList<LegoEventNotificationParam>

// SYNTHETIC: LEGO1 0x1005bd50
// MxCollection<LegoEventNotificationParam>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1005bdc0
// MxList<LegoEventNotificationParam>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1005beb0
// LegoEventQueue::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1005bf20
// MxQueue<LegoEventNotificationParam>::~MxQueue<LegoEventNotificationParam>

// SYNTHETIC: LEGO1 0x1005bf70
// MxQueue<LegoEventNotificationParam>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1005d010
// MxListEntry<LegoEventNotificationParam>::GetValue

#endif // LEGOINPUTMANAGER_H
