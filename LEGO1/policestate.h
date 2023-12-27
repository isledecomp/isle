#ifndef POLICESTATE_H
#define POLICESTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d8af0
// SIZE 0x10
class PoliceState : public LegoState {
public:
	PoliceState();

	// FUNCTION: LEGO1 0x1005e860
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0444
		return "PoliceState";
	}

	// FUNCTION: LEGO1 0x1005e870
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PoliceState::ClassName()) || LegoState::IsA(p_name);
	}
};

#endif // POLICESTATE_H
