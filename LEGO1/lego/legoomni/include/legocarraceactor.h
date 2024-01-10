#ifndef LEGOCARRACEACTOR_H
#define LEGOCARRACEACTOR_H

#include "legoraceactor.h"

// VTABLE: LEGO1 0x100da0d8
class LegoCarRaceActor : public LegoRaceActor {
public:
	// FUNCTION: LEGO1 0x10081650
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0568
		return "LegoCarRaceActor";
	}

	// FUNCTION: LEGO1 0x10081670
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCarRaceActor::ClassName()) || LegoRaceActor::IsA(p_name);
	}
};

#endif // LEGOCARRACEACTOR_H
