#ifndef PIZZERIASTATE_H
#define PIZZERIASTATE_H

#include "isleactor.h"

// VTABLE: LEGO1 0x100d5520
// SIZE 0x84
class Pizzeria : public IsleActor {
public:
	// FUNCTION: LEGO1 0x1000e780
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0380
		return "Pizzeria";
	}

	// FUNCTION: LEGO1 0x1000e790
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, Pizzeria::ClassName()) || IsleActor::IsA(name);
	}
};

#endif // PIZZERIASTATE_H
