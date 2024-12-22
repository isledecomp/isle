#ifndef BUILDINGENTITY_H
#define BUILDINGENTITY_H

#include "legoentity.h"

class LegoEventNotificationParam;

// VTABLE: LEGO1 0x100d5c88
// VTABLE: BETA10 0x101b9320
// SIZE 0x68
class BuildingEntity : public LegoEntity {
public:
	BuildingEntity();
	~BuildingEntity() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10014f20
	// FUNCTION: BETA10 0x10025f50
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07e8
		return "BuildingEntity";
	}

	// FUNCTION: LEGO1 0x10014f30
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, BuildingEntity::ClassName()) || LegoEntity::IsA(p_name);
	}

	virtual MxLong HandleClick(LegoEventNotificationParam& p_param) = 0;

	// SYNTHETIC: LEGO1 0x10015010
	// BuildingEntity::`scalar deleting destructor'
};

#endif // BUILDINGENTITY_H
