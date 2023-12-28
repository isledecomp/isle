#ifndef LEGOCONTROLMANAGER_H
#define LEGOCONTROLMANAGER_H

#include "mxcore.h"

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

	void Register(MxCore* p_listener);
	void Unregister(MxCore* p_listener);
};

#endif // LEGOCONTROLMANAGER_H
