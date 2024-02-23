#ifndef LEGOJETSKI_H
#define LEGOJETSKI_H

#include "legojetskiraceactor.h"

// VTABLE: LEGO1 0x100d5a40
class LegoJetski : public LegoJetskiRaceActor {
public:
	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10013e80
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f053c
		return "LegoJetski";
	}

	// FUNCTION: LEGO1 0x10013ea0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoJetski::ClassName()) || LegoJetskiRaceActor::IsA(p_name);
	}

	void ParseAction(char*) override;                  // vtable+0x20
	void SetWorldSpeed(MxFloat p_worldSpeed) override; // vtable+0x30
	void VTable0x6c() override;                        // vtable+0x6c
	void VTable0x70(float p_float) override;           // vtable+0x70
	MxS32 VTable0x94() override;                       // vtable+0x94
	void VTable0x98() override;                        // vtable+0x98
	void VTable0x9c() override;                        // vtable+0x9c

	// SYNTHETIC: LEGO1 0x10013e20
	// LegoJetski::`scalar deleting destructor'
};

#endif // LEGOJETSKI_H
