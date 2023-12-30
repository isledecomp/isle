#ifndef PIZZERIASTATE_H
#define PIZZERIASTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d5ee8
// SIZE 0xb4
class PizzeriaState : public LegoState {
public:
	PizzeriaState();

	// FUNCTION: LEGO1 0x10017c20
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0370
		return "PizzeriaState";
	}

	// FUNCTION: LEGO1 0x10017c30
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PizzeriaState::ClassName()) || LegoState::IsA(p_name);
	}
};

#endif // PIZZERIASTATE_H
