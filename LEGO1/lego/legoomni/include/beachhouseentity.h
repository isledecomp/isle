#ifndef BEACHHOUSEENTITY_H
#define BEACHHOUSEENTITY_H

#include "buildingentity.h"

// VTABLE: LEGO1 0x100d4a18
// SIZE 0x68
class BeachHouseEntity : public BuildingEntity {
public:
	virtual MxLong Notify(MxParam& p_param) override; // vtable+04

	// FUNCTION: LEGO1 0x1000ee80
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0314
		return "BeachHouseEntity";
	}

	// FUNCTION: LEGO1 0x1000ee90
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, BeachHouseEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}
};

#endif // BEACHHOUSEENTITY_H
