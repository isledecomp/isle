#ifndef GASSTATIONENTITY_H
#define GASSTATIONENTITY_H

#include "buildingentity.h"

// VTABLE 0x100d5258
// SIZE 0x68
class GasStationEntity : public BuildingEntity {
public:
	// OFFSET: LEGO1 0x1000eb20
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0348
		return "GasStationEntity";
	}

	// OFFSET: LEGO1 0x1000eb30
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, GasStationEntity::ClassName()) || BuildingEntity::IsA(name);
	}
};

#endif // GASSTATIONENTITY_H
