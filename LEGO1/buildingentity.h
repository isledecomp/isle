#ifndef BUILDINGENTITY_H
#define BUILDINGENTITY_H

#include "legoentity.h"

// VTABLE: LEGO1 0x100d5c88
// SIZE <= 0x68, hard to tell because it's always constructed as a derivative
class BuildingEntity : public LegoEntity {
public:
	BuildingEntity();
	virtual ~BuildingEntity() override; // vtable+0x0

	// FUNCTION: LEGO1 0x10014f20
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f07e8
		return "BuildingEntity";
	}

	// FUNCTION: LEGO1 0x10014f30
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, BuildingEntity::ClassName()) || LegoEntity::IsA(name);
	}
};

#endif // BUILDINGENTITY_H
