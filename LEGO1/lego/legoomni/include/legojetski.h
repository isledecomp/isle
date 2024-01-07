#ifndef LEGOJETSKI_H
#define LEGOJETSKI_H

#include "legojetskiraceactor.h"

// VTABLE: LEGO1 0x100d5a40
class LegoJetski : public LegoJetskiRaceActor {
public:
	// FUNCTION: LEGO1 0x10013e80
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f053c
		return "LegoJetski";
	}

	// FUNCTION: LEGO1 0x10013ea0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoJetski::ClassName()) || LegoJetskiRaceActor::IsA(p_name);
	}
};

#endif // LEGOJETSKI_H
