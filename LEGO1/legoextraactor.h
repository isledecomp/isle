#ifndef LEGOEXTRAACTOR_H
#define LEGOEXTRAACTOR_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d6c10
class LegoExtraActor : public LegoAnimActor {
public:
	// FUNCTION: LEGO1 0x1002b7a0
	inline const char* ClassName() const override // vtable+0xc
	{
		// 0x100f3204
		return "LegoExtraActor";
	}

	// FUNCTION: LEGO1 0x1002b7c0
	inline MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoExtraActor::ClassName()) || LegoAnimActor::IsA(name);
	}
};

#endif // LEGOEXTRAACTOR_H
