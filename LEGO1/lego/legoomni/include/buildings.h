#ifndef BUILDINGS_H
#define BUILDINGS_H

#include "buildingentity.h"

class LegoEventNotificationParam;

// VTABLE: LEGO1 0x100d48a8
// VTABLE: BETA10 0x101bd818
// SIZE 0x68
class RaceStandsEntity : public BuildingEntity {
	// FUNCTION: LEGO1 0x1000efa0
	// FUNCTION: BETA10 0x100a9820
	const char* ClassName() const override // vtable+0x0c
	{
		// at LEGO1 0x100f0300, needs no annotation
		return "RaceStandsEntity";
	}

	// FUNCTION: LEGO1 0x1000efb0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RaceStandsEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override;

	// SYNTHETIC: LEGO1 0x1000f9e0
	// RaceStandsEntity::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d4a18
// VTABLE: BETA10 0x101bd7b0
// SIZE 0x68
class BeachHouseEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000ee80
	// FUNCTION: BETA10 0x100a96f0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0314
		return "BeachHouseEntity";
	}

	// FUNCTION: LEGO1 0x1000ee90
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, BeachHouseEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override;

	// SYNTHETIC: LEGO1 0x1000f970
	// BeachHouseEntity::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d4ab0
// VTABLE: BETA10 0x101bd748
// SIZE 0x68
class PoliceEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000ed60
	// FUNCTION: BETA10 0x100a95c0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0328
		return "PoliceEntity";
	}

	// FUNCTION: LEGO1 0x1000ed70
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PoliceEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override; // vtable+0x50

	// SYNTHETIC: LEGO1 0x1000f900
	// PoliceEntity::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d4b90
// VTABLE: BETA10 0x101bd610
// SIZE 0x68
class InfoCenterEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000ea00
	// FUNCTION: BETA10 0x100a9230
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f035c
		return "InfoCenterEntity";
	}

	// FUNCTION: LEGO1 0x1000ea10
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, InfoCenterEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override; // vtable+0x50

	// SYNTHETIC: LEGO1 0x1000f7b0
	// InfoCenterEntity::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d5068
// VTABLE: BETA10 0x101bd678
// SIZE 0x68
class HospitalEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000ec40
	// FUNCTION: BETA10 0x100a9360
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0338
		return "HospitalEntity";
	}

	// FUNCTION: LEGO1 0x1000ec50
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, HospitalEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override; // vtable+0x50

	// SYNTHETIC: LEGO1 0x1000f820
	// HospitalEntity::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d50c0
// VTABLE: BETA10 0x101bd880
// SIZE 0x68
class CaveEntity : public BuildingEntity {
	// FUNCTION: LEGO1 0x1000f1e0
	// FUNCTION: BETA10 0x100a9950
	const char* ClassName() const override // vtable+0x0c
	{
		// at LEGO1 0x100f0300, needs no annotation
		return "RaceStandsEntity";
	}

	// FUNCTION: LEGO1 0x1000f1f0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, CaveEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override;

	// SYNTHETIC: LEGO1 0x1000fa50
	// CaveEntity::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d5200
// VTABLE: BETA10 0x101bd8e8
// SIZE 0x68
class JailEntity : public BuildingEntity {
	// FUNCTION: LEGO1 0x1000f0c0
	// FUNCTION: BETA10 0x100a9a80
	const char* ClassName() const override // vtable+0x0c
	{
		// at LEGO1 0x100f0300, needs no annotation
		return "RaceStandsEntity";
	}

	// FUNCTION: LEGO1 0x1000f0d0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JailEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override;

	// SYNTHETIC: LEGO1 0x1000fac0
	// JailEntity::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d5258
// VTABLE: BETA10 0x101bd6e0
// SIZE 0x68
class GasStationEntity : public BuildingEntity {
public:
	// FUNCTION: LEGO1 0x1000eb20
	// FUNCTION: BETA10 0x100a9490
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0348
		return "GasStationEntity";
	}

	// FUNCTION: LEGO1 0x1000eb30
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, GasStationEntity::ClassName()) || BuildingEntity::IsA(p_name);
	}

	MxLong HandleClick(LegoEventNotificationParam& p_param) override;

	// SYNTHETIC: LEGO1 0x1000f890
	// GasStationEntity::`scalar deleting destructor'
};

#endif // BUILDINGS_H
