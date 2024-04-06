#ifndef ISLEACTOR_H
#define ISLEACTOR_H

#include "legoactor.h"
#include "legoworld.h"
#include "mxactionnotificationparam.h"

// VTABLE: LEGO1 0x100d5178
// SIZE 0x7c
class IsleActor : public LegoActor {
public:
	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x1000e660
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07dc
		return "IsleActor";
	}

	// FUNCTION: LEGO1 0x1000e670
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, IsleActor::ClassName()) || LegoActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18

	// FUNCTION: LEGO1 0x1000e5f0
	virtual undefined4 VTable0x68() { return 0; } // vtable+0x68

	// FUNCTION: LEGO1 0x1000e600
	virtual undefined4 VTable0x6c() { return 0; } // vtable+0x6c

	// FUNCTION: LEGO1 0x1000e610
	virtual undefined4 VTable0x70() { return 0; } // vtable+0x70

	// FUNCTION: LEGO1 0x1000e620
	virtual undefined4 HandleEndAction(MxEndActionNotificationParam&) { return 0; } // vtable+0x74

	// FUNCTION: LEGO1 0x1000e630
	virtual undefined4 HandleButtonDown(MxNotificationParam&) { return 0; } // vtable+0x78

	// FUNCTION: LEGO1 0x1000e640
	virtual undefined4 HandleButtonUp(MxNotificationParam&) { return 0; } // vtable+0x7c

	// FUNCTION: LEGO1 0x1000e650
	virtual undefined4 VTable0x80(MxParam&) { return 0; } // vtable+0x80

private:
	LegoWorld* m_world; // 0x78
};

// SYNTHETIC: LEGO1 0x1000e940
// IsleActor::~IsleActor

// SYNTHETIC: LEGO1 0x1000e990
// IsleActor::`scalar deleting destructor'

#endif // ISLEACTOR_H
