#ifndef HOSPITAL_H
#define HOSPITAL_H

#include "legoworld.h"

// VTABLE: LEGO1 0x100d9730
// SIZE 0x12c
class Hospital : public LegoWorld {
public:
	Hospital();
	virtual ~Hospital() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x100746b0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0490
		return "Hospital";
	}

	// FUNCTION: LEGO1 0x100746c0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Hospital::ClassName()) || LegoWorld::IsA(p_name);
	}
};

#endif // HOSPITAL_H
