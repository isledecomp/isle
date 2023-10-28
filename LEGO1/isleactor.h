#ifndef ISLEACTOR_H
#define ISLEACTOR_H

#include "legoactor.h"

// VTABLE 0x100d5178
class IsleActor : public LegoActor {
public:
	// OFFSET: LEGO1 0x1000e660
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f07dc
		return "IsleActor";
	}

	// OFFSET: LEGO1 0x1000e670
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, IsleActor::ClassName()) || LegoActor::IsA(name);
	}
};

#endif // ISLEACTOR_H
