#ifndef RADIOSTATE_H
#define RADIOSTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d6d28
// SIZE 0x30
class RadioState : public LegoState {
public:
	RadioState();

	// FUNCTION: LEGO1 0x1002cf60
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04f8
		return "RadioState";
	}

	// FUNCTION: LEGO1 0x1002cf70
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RadioState::ClassName()) || LegoState::IsA(p_name);
	}

	virtual MxBool VTable0x14() override; // vtable+0x14

	// SYNTHETIC: LEGO1 0x1002d020
	// RadioState::`scalar deleting destructor'
};

#endif // RADIOSTATE_H
