#ifndef LEGOJETSKI_H
#define LEGOJETSKI_H

#include "legojetskiraceactor.h"

// VTABLE: LEGO1 0x100d5a40
class LegoJetski : public LegoJetskiRaceActor {
public:
	// FUNCTION: LEGO1 0x10013e80
	inline const char* ClassName() const override // vtable+0xc
	{
		// GLOBAL: LEGO1 0x100f053c
		return "LegoJetski";
	}

	// FUNCTION: LEGO1 0x10013ea0
	inline MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoJetski::ClassName()) || LegoJetskiRaceActor::IsA(name);
	}
};

#endif // LEGOJETSKI_H
