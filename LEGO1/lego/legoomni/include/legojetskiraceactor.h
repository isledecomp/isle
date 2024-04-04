#ifndef LEGOJETSKIRACEACTOR_H
#define LEGOJETSKIRACEACTOR_H

#include "legocarraceactor.h"

/*
	VTABLE: LEGO1 0x100da208 LegoCarRaceActor
	VTABLE: LEGO1 0x100da228 LegoRaceActor
	VTABLE: LEGO1 0x100da230 LegoAnimActor
	VTABLE: LEGO1 0x100da240 LegoPathActor
*/
// SIZE 0x1a8
class LegoJetskiRaceActor : public virtual LegoCarRaceActor {
public:
	LegoJetskiRaceActor();

	// FUNCTION: LEGO1 0x10081d80
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0554
		return "LegoJetskiRaceActor";
	}

	// FUNCTION: LEGO1 0x10081da0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoJetskiRaceActor::ClassName()) || LegoCarRaceActor::IsA(p_name);
	}

	void VTable0x6c() override;              // vtable+0x6c
	void VTable0x70(float p_float) override; // vtable+0x70
	void VTable0x98() override;              // vtable+0x98
	MxResult WaitForAnimation() override;    // vtable+0x9c
	void VTable0x1c() override;              // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10081d40
	// LegoJetskiRaceActor::`scalar deleting destructor'
};

#endif // LEGOJETSKIRACEACTOR_H
