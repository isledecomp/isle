#ifndef POLICESTATE_H
#define POLICESTATE_H

#include "decomp.h"
#include "legostate.h"

// VTABLE: LEGO1 0x100d8af0
// SIZE 0x10
class PoliceState : public LegoState {
public:
	PoliceState();
	~PoliceState() override {}

	// FUNCTION: LEGO1 0x1005e860
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0444
		return "PoliceState";
	}

	// FUNCTION: LEGO1 0x1005e870
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PoliceState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult VTable0x1c(LegoFile* p_legoFile) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x1005e920
	// PoliceState::`scalar deleting destructor'

private:
	undefined4 m_unk0x08; // 0x08
	undefined4 m_unk0x0c; // 0x0c
};

#endif // POLICESTATE_H
