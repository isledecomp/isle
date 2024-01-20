#ifndef POLICESTATE_H
#define POLICESTATE_H

#include "decomp.h"
#include "legostate.h"

// VTABLE: LEGO1 0x100d8af0
// SIZE 0x10
class PoliceState : public LegoState {
public:
	PoliceState();

	// FUNCTION: LEGO1 0x1005e860
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0444
		return "PoliceState";
	}

	// FUNCTION: LEGO1 0x1005e870
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PoliceState::ClassName()) || LegoState::IsA(p_name);
	}

	virtual MxResult VTable0x1c(LegoFileStream* p_legoFileStream) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x1005e920
	// PoliceState::`scalar deleting destructor'

private:
	undefined4 m_unk0x8; // 0x8
	undefined4 m_unk0xc; // 0xc
};

#endif // POLICESTATE_H
