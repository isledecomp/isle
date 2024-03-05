#ifndef JAILENTITY_H
#define JAILENTITY_H

#include "buildingentity.h"

// VTABLE: LEGO1 0x100d5200
// SIZE 0x68
class JailEntity : public BuildingEntity {
	// FUNCTION: LEGO1 0x1000f0c0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0300
		return "RaceStandsEntity";
	}

	// FUNCTION: LEGO1 0x1000f0d0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JailEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	// STUB: LEGO1 0x100154f0
	MxLong VTable0x50(MxParam& p_param) override { return 0; }

	// SYNTHETIC: LEGO1 0x1000fac0
	// JailEntity::`scalar deleting destructor'
};

#endif // JAILENTITY_H
