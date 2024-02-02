#ifndef GASSTATIONSTATE_H
#define GASSTATIONSTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d46e0
// SIZE 0x24
class GasStationState : public LegoState {
public:
	GasStationState();

	// FUNCTION: LEGO1 0x100061d0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0174
		return "GasStationState";
	}

	// FUNCTION: LEGO1 0x100061e0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, GasStationState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult VTable0x1c(LegoFile* p_legoFile) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10006290
	// GasStationState::`scalar deleting destructor'

private:
	undefined4 m_unk0x08[3]; // 0x08
	undefined4 m_unk0x14;    // 0x14
	undefined2 m_unk0x18;    // 0x18
	undefined2 m_unk0x1a;    // 0x1a
	undefined2 m_unk0x1c;    // 0x1c
	undefined2 m_unk0x1e;    // 0x1e
	undefined2 m_unk0x20;    // 0x20
};

#endif // GASSTATIONSTATE_H
