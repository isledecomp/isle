#ifndef LEGORACEACTOR_H
#define LEGORACEACTOR_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d5b88
class LegoRaceActor : public LegoAnimActor {
public:
	// FUNCTION: LEGO1 0x10014af0
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0bf4
		return "LegoRaceActor";
	}

	// FUNCTION: LEGO1 0x10014b10
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoRaceActor::ClassName()) || LegoAnimActor::IsA(p_name);
	}
};

#endif // LEGORACEACTOR_H
