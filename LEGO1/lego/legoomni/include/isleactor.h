#ifndef ISLEACTOR_H
#define ISLEACTOR_H

#include "legoactor.h"

class LegoControlManagerNotificationParam;
class LegoPathStructNotificationParam;
class LegoWorld;
class MxEndActionNotificationParam;
class MxNotificationParam;

// VTABLE: LEGO1 0x100d5178
// VTABLE: BETA10 0x101bd150
// SIZE 0x7c
class IsleActor : public LegoActor {
public:
	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x1000e660
	// FUNCTION: BETA10 0x100a8300
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07dc
		return "IsleActor";
	}

	// FUNCTION: LEGO1 0x1000e670
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, IsleActor::ClassName()) || LegoActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18

	// FUNCTION: LEGO1 0x1000e5f0
	virtual MxLong HandleClick() { return 0; } // vtable+0x68

	// FUNCTION: LEGO1 0x1000e600
	virtual MxLong VTable0x6c() { return 0; } // vtable+0x6c

	// FUNCTION: LEGO1 0x1000e610
	virtual MxLong HandleEndAnim() { return 0; } // vtable+0x70

	// FUNCTION: LEGO1 0x1000e620
	virtual MxLong HandleEndAction(MxEndActionNotificationParam&) { return 0; } // vtable+0x74

	// FUNCTION: LEGO1 0x1000e630
	virtual MxLong HandleButtonDown(LegoControlManagerNotificationParam&) { return 0; } // vtable+0x78

	// FUNCTION: LEGO1 0x1000e640
	virtual MxLong HandleButtonUp(LegoControlManagerNotificationParam&) { return 0; } // vtable+0x7c

	// FUNCTION: LEGO1 0x1000e650
	virtual MxLong HandlePathStruct(LegoPathStructNotificationParam&) { return 0; } // vtable+0x80

protected:
	LegoWorld* m_world; // 0x78
};

// SYNTHETIC: LEGO1 0x1000e940
// IsleActor::~IsleActor

// SYNTHETIC: LEGO1 0x1000e990
// IsleActor::`scalar deleting destructor'

#endif // ISLEACTOR_H
