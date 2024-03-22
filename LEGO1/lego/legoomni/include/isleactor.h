#ifndef ISLEACTOR_H
#define ISLEACTOR_H

#include "legoactor.h"

// VTABLE: LEGO1 0x100d5178
// SIZE 0x78
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
};

// SYNTHETIC: LEGO1 0x1000e940
// IsleActor::~IsleActor

// SYNTHETIC: LEGO1 0x1000e990
// IsleActor::`scalar deleting destructor'

#endif // ISLEACTOR_H
