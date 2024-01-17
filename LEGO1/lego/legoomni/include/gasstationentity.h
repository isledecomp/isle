#ifndef GASSTATIONENTITY_H
#define GASSTATIONENTITY_H

#include "buildingentity.h"

// VTABLE: LEGO1 0x100d5258
// SIZE 0x68
class GasStationEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000eb20
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0348
		return "GasStationEntity";
	}

	// FUNCTION: LEGO1 0x1000eb30
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, GasStationEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x1000f890
	// GasStationEntity::`scalar deleting destructor'
};

#endif // GASSTATIONENTITY_H
