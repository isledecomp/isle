#ifndef BIKE_H
#define BIKE_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d9808
// VTABLE: BETA10 0x101b91e8
// SIZE 0x164
class Bike : public IslePathActor {
public:
	Bike();

	// FUNCTION: LEGO1 0x100766f0
	// FUNCTION: BETA10 0x10024bd0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03d0
		return "Bike";
	}

	// FUNCTION: LEGO1 0x10076700
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Bike::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                            // vtable+0x18
	MxLong HandleClick() override;                                               // vtable+0xcc
	MxLong HandleControl(LegoControlManagerNotificationParam& p_param) override; // vtable+0xd4
	void Exit() override;                                                        // vtable+0xe4

	void ActivateSceneActions();

	// SYNTHETIC: LEGO1 0x10076880
	// Bike::`scalar deleting destructor'

private:
	// TODO: Bike fields
	undefined m_unk0x160[4];
};

#endif // BIKE_H
