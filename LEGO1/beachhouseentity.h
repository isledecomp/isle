#ifndef BEACHHOUSEENTITY_H
#define BEACHHOUSEENTITY_H

#include "buildingentity.h"

// VTABLE 0x100d4a18
// SIZE 0x68
class BeachHouseEntity : public BuildingEntity {
public:
	virtual MxLong Notify(MxParam& p) override; // vtable+04

	// OFFSET: LEGO1 0x1000ee80
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0314
		return "BeachHouseEntity";
	}

	// OFFSET: LEGO1 0x1000ee90
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, BeachHouseEntity::ClassName()) || BuildingEntity::IsA(name);
	}
};

#endif // BEACHHOUSEENTITY_H
