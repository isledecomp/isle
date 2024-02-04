#ifndef LEGOCONTROLMANAGER_H
#define LEGOCONTROLMANAGER_H

#include "legoeventnotificationparam.h"
#include "legoinputmanager.h"
#include "mxcore.h"
#include "mxpresenterlist.h"

class MxControlPresenter;

// VTABLE: LEGO1 0x100d6a98
// SIZE 0x2c
class LegoControlManagerEvent : public LegoEventNotificationParam {
public:
	inline LegoControlManagerEvent() : LegoEventNotificationParam()
	{
		m_clickedObjectId = -1;
		m_clickedAtom = NULL;
	}

	inline MxS32 GetClickedObjectId() const { return m_clickedObjectId; }
	inline const char* GetClickedAtom() const { return m_clickedAtom; }
	inline MxS16 GetUnknown0x28() const { return m_unk0x28; }

	inline void SetClickedObjectId(MxS32 p_clickedObjectId) { m_clickedObjectId = p_clickedObjectId; }
	inline void SetClickedAtom(const char* p_clickedAtom) { m_clickedAtom = p_clickedAtom; }
	inline void SetUnknown0x28(MxS16 p_unk0x28) { m_unk0x28 = p_unk0x28; }

private:
	MxS32 m_clickedObjectId;   // 0x20
	const char* m_clickedAtom; // 0x24
	MxS16 m_unk0x28;           // 0x28
};

// SYNTHETIC: LEGO1 0x10028bf0
// LegoControlManagerEvent::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10028c60
// LegoControlManagerEvent::~LegoControlManagerEvent

// VTABLE: LEGO1 0x100d6a80
class LegoControlManager : public MxCore {
public:
	LegoControlManager();
	~LegoControlManager() override; // vtable+0x00

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x10028cb0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f31b8
		return "LegoControlManager";
	}

	// FUNCTION: LEGO1 0x10028cc0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoControlManager::ClassName()) || MxCore::IsA(p_name);
	}

	void FUN_10028df0(MxPresenterList* p_presenterList);
	void Register(MxCore* p_listener);
	void Unregister(MxCore* p_listener);
	MxBool FUN_10029210(LegoEventNotificationParam& p_param, MxPresenter* p_presenter);
	void FUN_100293c0(undefined4, const char*, undefined2);
	MxControlPresenter* FUN_100294e0(MxS32 p_x, MxS32 p_y);
	MxBool FUN_10029630();
	MxBool FUN_10029750();
	void FUN_100292e0();

	inline undefined4 GetUnknown0x0c() { return m_unk0x0c; }
	inline undefined GetUnknown0x10() { return m_unk0x10; }

	// SYNTHETIC: LEGO1 0x10028d40
	// LegoControlManager::`scalar deleting destructor'

private:
	undefined4 m_unk0x08;             // 0x08
	undefined4 m_unk0x0c;             // 0x0c
	MxBool m_unk0x10;                 // 0x10
	MxPresenter* m_unk0x14;           // 0x14
	LegoControlManagerEvent m_event;  // 0x18
	MxPresenterList* m_presenterList; // 0x44
	LegoNotifyList m_notifyList;      // 0x48
};

#endif // LEGOCONTROLMANAGER_H
