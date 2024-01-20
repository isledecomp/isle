#ifndef BUILDINGENTITY_H
#define BUILDINGENTITY_H

#include "legoentity.h"

// VTABLE: LEGO1 0x100d5c88
// SIZE <= 0x68, hard to tell because it's always constructed as a derivative
class BuildingEntity : public LegoEntity {
public:
	BuildingEntity();
	virtual ~BuildingEntity() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4

	// FUNCTION: LEGO1 0x10014f20
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07e8
		return "BuildingEntity";
	}

	// FUNCTION: LEGO1 0x10014f30
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, BuildingEntity::ClassName()) || LegoEntity::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x10015010
	// BuildingEntity::`scalar deleting destructor'
};

#endif // BUILDINGENTITY_H
