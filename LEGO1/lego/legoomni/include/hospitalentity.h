#ifndef HOSPITALENTITY_H
#define HOSPITALENTITY_H

#include "buildingentity.h"

// VTABLE: LEGO1 0x100d5068
// SIZE 0x68
class HospitalEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000ec40
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0338
		return "HospitalEntity";
	}

	// FUNCTION: LEGO1 0x1000ec50
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, HospitalEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong VTable0x50(MxParam& p_param) override; // vtable+0x50

	// SYNTHETIC: LEGO1 0x1000f820
	// HospitalEntity::`scalar deleting destructor'
};

#endif // HOSPITALENTITY_H
