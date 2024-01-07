#ifndef ELEVATORBOTTOM_H
#define ELEVATORBOTTOM_H

#include "legoworld.h"

// VTABLE: LEGO1 0x100d5f20
class ElevatorBottom : public LegoWorld {
public:
	ElevatorBottom();
	virtual ~ElevatorBottom() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4

	// FUNCTION: LEGO1 0x10017f20
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04ac
		return "ElevatorBottom";
	}

	// FUNCTION: LEGO1 0x10017f30
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ElevatorBottom::ClassName()) || LegoWorld::IsA(p_name);
	}
};

#endif // ELEVATORBOTTOM_H
