#ifndef BEACHHOUSEENTITY_H
#define BEACHHOUSEENTITY_H

#include "buildingentity.h"

// VTABLE: LEGO1 0x100d4a18
// SIZE 0x68
class BeachHouseEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000ee80
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0314
		return "BeachHouseEntity";
	}

	// FUNCTION: LEGO1 0x1000ee90
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, BeachHouseEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x1000f970
	// BeachHouseEntity::`scalar deleting destructor'
};

#endif // BEACHHOUSEENTITY_H
