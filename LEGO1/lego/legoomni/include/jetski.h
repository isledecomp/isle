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

	void FUN_1007e990();

	inline MxS16 GetUnknown0x160() { return m_unk0x160; }

	// SYNTHETIC: LEGO1 0x1007e5c0
	// Jetski::`scalar deleting destructor'

private:
	// TODO: Jetski fields
	MxS16 m_unk0x160;        // 0x160
	undefined m_unk0x162[2]; // 0x162
};

#endif // JETSKI_H
