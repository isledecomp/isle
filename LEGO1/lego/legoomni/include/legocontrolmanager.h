#ifndef LEGOCONTROLMANAGER_H
#define LEGOCONTROLMANAGER_H

#include "legoeventnotificationparam.h"
#include "mxcore.h"
#include "mxpresenterlist.h"

// VTABLE: LEGO1 0x100d6a80
class LegoControlManager : public MxCore {
public:
	LegoControlManager();
	virtual ~LegoControlManager() override; // vtable+0x0

	virtual MxResult Tickle() override; // vtable+0x8

	// FUNCTION: LEGO1 0x10028cb0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f31b8
		return "LegoControlManager";
	}

	// FUNCTION: LEGO1 0x10028cc0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoControlManager::ClassName()) || MxCore::IsA(p_name);
	}

	void FUN_10028df0(MxPresenterList* p_presenterList);
	void Register(MxCore* p_listener);
	void Unregister(MxCore* p_listener);
	MxBool FUN_10029210(LegoEventNotificationParam& p_param, MxPresenter* p_presenter);
	void FUN_100293c0(undefined4, const char*, undefined2);

	inline undefined4 GetUnknown0x0c() { return m_unk0x0c; }
	inline undefined GetUnknown0x10() { return m_unk0x10; }

	// SYNTHETIC: LEGO1 0x10028d40
	// LegoControlManager::`scalar deleting destructor'

private:
	undefined4 m_unk0x08;          // 0x08
	undefined4 m_unk0x0c;          // 0x0c
	undefined m_unk0x10;           // 0x10
	undefined m_padding0x14[0x4c]; // 0x14
};

#endif // LEGOCONTROLMANAGER_H
