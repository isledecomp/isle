#ifndef BUILDINGS_H
#define BUILDINGS_H

#include "buildingentity.h"

class LegoEventNotificationParam;

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

	MxLong HandleClick(LegoEventNotificationParam& p_param) override;

	// SYNTHETIC: LEGO1 0x1000f9e0
	// RaceStandsEntity::`scalar deleting destructor'
};

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

	MxLong HandleClick(LegoEventNotificationParam& p_param) override;

	// SYNTHETIC: LEGO1 0x1000f970
	// BeachHouseEntity::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d4ab0
// SIZE 0x68
class PoliceEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000ed60
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0328
		return "PoliceEntity";
	}

	// FUNCTION: LEGO1 0x1000ed70
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PoliceEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override; // vtable+0x50

	// SYNTHETIC: LEGO1 0x1000f900
	// PoliceEntity::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d4b90
// SIZE 0x68
class InfoCenterEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000ea00
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f035c
		return "InfoCenterEntity";
	}

	// FUNCTION: LEGO1 0x1000ea10
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, InfoCenterEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override; // vtable+0x50

	// SYNTHETIC: LEGO1 0x1000f7b0
	// InfoCenterEntity::`scalar deleting destructor'
};

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

	MxLong HandleClick(LegoEventNotificationParam& p_param) override; // vtable+0x50

	// SYNTHETIC: LEGO1 0x1000f820
	// HospitalEntity::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d50c0
// SIZE 0x68
class CaveEntity : public BuildingEntity {
	// FUNCTION: LEGO1 0x1000f1e0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0300
		return "RaceStandsEntity";
	}

	// FUNCTION: LEGO1 0x1000f1f0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, CaveEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override;

	// SYNTHETIC: LEGO1 0x1000fa50
	// CaveEntity::`scalar deleting destructor'
};

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

	MxLong HandleClick(LegoEventNotificationParam& p_param) override;

	// SYNTHETIC: LEGO1 0x1000fac0
	// JailEntity::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d5258
// SIZE 0x68
class GasStationEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000eb20
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0348
		return "GasStationEntity";
	}

	// FUNCTION: LEGO1 0x1000eb30
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, GasStationEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override;

	// SYNTHETIC: LEGO1 0x1000f890
	// GasStationEntity::`scalar deleting destructor'
};

#endif // BUILDINGS_H
