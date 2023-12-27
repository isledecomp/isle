#ifndef ISLEACTOR_H
#define ISLEACTOR_H

#include "legoactor.h"

// VTABLE: LEGO1 0x100d5178
class IsleActor : public LegoActor {
public:
	// FUNCTION: LEGO1 0x1000e660
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07dc
		return "IsleActor";
	}

	// FUNCTION: LEGO1 0x1000e670
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, IsleActor::ClassName()) || LegoActor::IsA(p_name);
	}
};

#endif // ISLEACTOR_H
