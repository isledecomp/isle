#ifndef JETSKIRACE_H
#define JETSKIRACE_H

#include "legorace.h"

// VTABLE: LEGO1 0x100d4fe8
// SIZE 0x144
class JetskiRace : public LegoRace {
public:
	// FUNCTION: LEGO1 0x1000daf0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0530
		return "JetskiRace";
	}

	// FUNCTION: LEGO1 0x1000db00
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, JetskiRace::ClassName()) || LegoRace::IsA(name);
	}
};

#endif // JETSKIRACE_H
