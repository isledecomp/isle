#ifndef POLICESTATE_H
#define POLICESTATE_H

#include "legostate.h"

// VTABLE 0x100d8af0
// SIZE 0x10
class PoliceState : public LegoState {
public:
	PoliceState();

	// OFFSET: LEGO1 0x1005e860
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0444
		return "PoliceState";
	}

	// OFFSET: LEGO1 0x1005e870
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, PoliceState::ClassName()) || LegoState::IsA(name);
	}
};

#endif // POLICESTATE_H
