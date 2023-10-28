#ifndef INFOCENTERENTITY_H
#define INFOCENTERENTITY_H

#include "buildingentity.h"

// VTABLEADDR 0x100d4b90
// SIZE 0x68
class InfoCenterEntity : public BuildingEntity {
public:
	// OFFSET: LEGO1 0x1000ea00
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f035c
		return "InfoCenterEntity";
	}

	// OFFSET: LEGO1 0x1000ea10
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, InfoCenterEntity::ClassName()) || BuildingEntity::IsA(name);
	}
};

#endif // INFOCENTERENTITY_H
