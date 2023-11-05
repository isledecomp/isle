#ifndef PIZZERIASTATE_H
#define PIZZERIASTATE_H

#include "legostate.h"

// VTABLE 0x100d5ee8
// SIZE 0xb4
class PizzeriaState : public LegoState {
public:
	PizzeriaState();

	// OFFSET: LEGO1 0x10017c20
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0370
		return "PizzeriaState";
	}

	// OFFSET: LEGO1 0x10017c30
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, PizzeriaState::ClassName()) || LegoState::IsA(name);
	}
};

#endif // PIZZERIASTATE_H
