#ifndef BUMPBOUY_H
#define BUMPBOUY_H

#include "legoanimactor.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d6790
class BumpBouy : public LegoAnimActor {
public:
	// FUNCTION: LEGO1 0x100274e0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0394
		return "BumpBouy";
	}

	// FUNCTION: LEGO1 0x10027500
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, BumpBouy::ClassName()) || LegoAnimActor::IsA(p_name);
	}
};

#endif // BUMPBOUY_H
