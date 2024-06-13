#ifndef MOTOCYCLE_H
#define MOTOCYCLE_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d7090
// SIZE 0x16c
class Motocycle : public IslePathActor {
public:
	Motocycle();

	// FUNCTION: LEGO1 0x10035840
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f38e8
		return "Motorcycle";
	}

	// FUNCTION: LEGO1 0x10035850
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Motocycle::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                // vtable+0x18
	void VTable0x70(float p_float) override;                         // vtable+0x70
	MxLong HandleClick() override;                                   // vtable+0xcc
	MxLong HandleControl(LegoControlManagerEvent& p_param) override; // vtable+0xd4
	MxLong HandlePathStruct(LegoPathStructEvent&) override;          // vtable+0xdc
	void Exit() override;                                            // vtable+0xe4

	void FUN_10035e10();

	// SYNTHETIC: LEGO1 0x100359d0
	// Motocycle::`scalar deleting destructor'

private:
	undefined m_unk0x160[4];
	MxFloat m_unk0x164;
	undefined m_unk0x168[4];
};

#endif // MOTOCYCLE_H
