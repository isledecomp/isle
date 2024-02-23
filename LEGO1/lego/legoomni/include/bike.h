#ifndef BIKE_H
#define BIKE_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d9808
// SIZE 0x164
class Bike : public IslePathActor {
public:
	Bike();

	// FUNCTION: LEGO1 0x100766f0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03d0
		return "Bike";
	}

	// FUNCTION: LEGO1 0x10076700
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Bike::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;            // vtable+0x18
	MxU32 VTable0xcc() override;                                 // vtable+0xcc
	MxU32 VTable0xd4(LegoControlManagerEvent& p_param) override; // vtable+0xd4
	void VTable0xe4() override;                                  // vtable+0xe4

	// SYNTHETIC: LEGO1 0x10076880
	// Bike::`scalar deleting destructor'

private:
	// TODO: Bike fields
	undefined m_unk0x160[4];
};

#endif // BIKE_H
