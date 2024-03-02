#ifndef RACESTANDSENTITY_H
#define RACESTANDSENTITY_H

#include "buildingentity.h"

// VTABLE: LEGO1 0x100d48a8
// SIZE 0x68
class RaceStandsEntity : public BuildingEntity {
	// FUNCTION: LEGO1 0x1000efa0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0300
		return "RaceStandsEntity";
	}

	// FUNCTION: LEGO1 0x1000efb0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RaceStandsEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	// STUB: LEGO1 0x10015450
	MxLong VTable0x50(MxParam& p_param) override { return 0; }

	// SYNTHETIC: LEGO1 0x1000f9e0
	// RaceStandsEntity::`scalar deleting destructor'
};

#endif // RACESTANDSENTITY_H
