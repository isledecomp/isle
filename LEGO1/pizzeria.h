#ifndef PIZZERIA_H
#define PIZZERIA_H

#include "isleactor.h"

// VTABLE: LEGO1 0x100d5520
// SIZE 0x84
class Pizzeria : public IsleActor {
public:
	// FUNCTION: LEGO1 0x1000e780
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0380
		return "Pizzeria";
	}

	// FUNCTION: LEGO1 0x1000e790
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Pizzeria::ClassName()) || IsleActor::IsA(p_name);
	}
};

#endif // PIZZERIA_H
