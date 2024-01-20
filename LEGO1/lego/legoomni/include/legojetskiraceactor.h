#ifndef LEGOJETSKIRACEACTOR_H
#define LEGOJETSKIRACEACTOR_H

#include "legocarraceactor.h"

// VTABLE: LEGO1 0x100da240
class LegoJetskiRaceActor : public LegoCarRaceActor {
public:
	// FUNCTION: LEGO1 0x10081d80
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0554
		return "LegoJetskiRaceActor";
	}

	// FUNCTION: LEGO1 0x10081da0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoJetskiRaceActor::ClassName()) || LegoCarRaceActor::IsA(p_name);
	}

	virtual void VTable0x6c() override;              // vtable+0x6c
	virtual void VTable0x70(float p_float) override; // vtable+0x70
	virtual void VTable0x98() override;              // vtable+0x98
	virtual void VTable0x9c() override;              // vtable+0x9c

	// SYNTHETIC: LEGO1 0x10081d40
	// LegoJetskiRaceActor::`scalar deleting destructor'
};

#endif // LEGOJETSKIRACEACTOR_H
