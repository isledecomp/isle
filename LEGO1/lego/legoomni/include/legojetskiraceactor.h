#ifndef LEGOJETSKIRACEACTOR_H
#define LEGOJETSKIRACEACTOR_H

#include "legocarraceactor.h"

// VTABLE: LEGO1 0x100da240
class LegoJetskiRaceActor : public LegoCarRaceActor {
public:
	// FUNCTION: LEGO1 0x10081d80
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0554
		return "LegoJetskiRaceActor";
	}

	// FUNCTION: LEGO1 0x10081da0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoJetskiRaceActor::ClassName()) || LegoCarRaceActor::IsA(p_name);
	}
};

#endif // LEGOJETSKIRACEACTOR_H
