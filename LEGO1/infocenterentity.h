#ifndef INFOCENTERENTITY_H
#define INFOCENTERENTITY_H

#include "buildingentity.h"

// VTABLE: LEGO1 0x100d4b90
// SIZE 0x68
class InfoCenterEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000ea00
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f035c
		return "InfoCenterEntity";
	}

	// FUNCTION: LEGO1 0x1000ea10
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, InfoCenterEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}
};

#endif // INFOCENTERENTITY_H
