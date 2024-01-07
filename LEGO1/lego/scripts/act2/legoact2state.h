#ifndef LEGOACT2STATE_H
#define LEGOACT2STATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d4a70
// SIZE 0x10
class LegoAct2State : public LegoState {
public:
	// FUNCTION: LEGO1 0x1000df80
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0428
		return "LegoAct2State";
	}

	// FUNCTION: LEGO1 0x1000df90
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAct2State::ClassName()) || LegoState::IsA(p_name);
	}
};

#endif // LEGOACT2STATE_H
