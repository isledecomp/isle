#ifndef JETSKI_H
#define JETSKI_H

#include "decomp.h"
#include "islepathactor.h"
#include "legocontrolmanager.h"

// VTABLE: LEGO1 0x100d9ec8
// SIZE 0x164
class Jetski : public IslePathActor {
public:
	Jetski();

	// FUNCTION: LEGO1 0x1007e430
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03d8
		return "Jetski";
	}

	// FUNCTION: LEGO1 0x1007e440
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Jetski::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;    // vtable+0x18
	void VTable0x70(float p_float) override;             // vtable+0x70
	MxU32 VTable0xcc() override;                         // vtable+0xcc
	MxU32 VTable0xd4(LegoControlManagerEvent&) override; // vtable+0xd4
	void VTable0xe4() override;                          // vtable+0xe4

	// SYNTHETIC: LEGO1 0x1007e5c0
	// Jetski::`scalar deleting destructor'

private:
	// TODO: Jetski fields
	undefined m_unk0x160[4];
};

#endif // JETSKI_H
