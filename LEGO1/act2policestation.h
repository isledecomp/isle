#ifndef ACT2POLICESTATION_H
#define ACT2POLICESTATION_H

#include "legoentity.h"

// VTABLE: LEGO1 0x100d53a8
// SIZE 0x68
class Act2PoliceStation : public LegoEntity {
public:
	virtual MxLong Notify(MxParam& p) override; // vtable+0x4

	// FUNCTION: LEGO1 0x1000e200
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f03fc
		return "Act2PoliceStation";
	}

	// FUNCTION: LEGO1 0x1000e210
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, Act2PoliceStation::ClassName()) || LegoEntity::IsA(name);
	}
};

#endif // ACT2POLICESTATION_H
