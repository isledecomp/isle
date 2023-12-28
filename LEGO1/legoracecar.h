#ifndef LEGOCARRACE_H
#define LEGOCARRACE_H

#include "legocarraceactor.h"
#include "legopathactor.h"

// VTABLE: LEGO1 0x100d58b8
// SIZE 0x200
class LegoRaceCar : public LegoCarRaceActor {
public:
	// FUNCTION: LEGO1 0x10014290
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0548
		return "LegoRaceCar";
	}

	// FUNCTION: LEGO1 0x100142b0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCarRaceActor::ClassName()) || LegoCarRaceActor::IsA(p_name);
	}
};

#endif // LEGOCARRACE_H
