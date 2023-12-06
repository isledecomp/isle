#ifndef POLICEENTITY_H
#define POLICEENTITY_H

#include "buildingentity.h"

// VTABLE: LEGO1 0x100d4ab0
// SIZE 0x68
class PoliceEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000ed60
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// GLOBAL: LEGO1 0x100f0328
		return "PoliceEntity";
	}

	// FUNCTION: LEGO1 0x1000ed70
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, PoliceEntity::ClassName()) || BuildingEntity::IsA(name);
	}
};

#endif // POLICEENTITY_H
