#ifndef MOTORCYCLE_H
#define MOTORCYCLE_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d7090
// VTABLE: BETA10 0x101bf3d8
// SIZE 0x16c
class Motocycle : public IslePathActor {
public:
	Motocycle();

	// FUNCTION: LEGO1 0x10035840
	// FUNCTION: BETA10 0x100e83c0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f38e8
		return "Motorcycle";
	}

	// FUNCTION: LEGO1 0x10035850
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Motocycle::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                            // vtable+0x18
	void Animate(float p_time) override;                                         // vtable+0x70
	MxLong HandleClick() override;                                               // vtable+0xcc
	MxLong HandleControl(LegoControlManagerNotificationParam& p_param) override; // vtable+0xd4
	MxLong HandlePathStruct(LegoPathStructNotificationParam&) override;          // vtable+0xdc
	void Exit() override;                                                        // vtable+0xe4

	void ActivateSceneActions();

	// SYNTHETIC: LEGO1 0x100359d0
	// Motocycle::`scalar deleting destructor'

private:
	undefined m_unk0x160[4]; // 0x160
	MxFloat m_fuel;          // 0x164
	MxFloat m_time;          // 0x168
};

#endif // MOTORCYCLE_H
