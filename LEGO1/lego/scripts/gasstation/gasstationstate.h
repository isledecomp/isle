#ifndef GASSTATIONSTATE_H
#define GASSTATIONSTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d46e0
// SIZE 0x24
class GasStationState : public LegoState {
public:
	GasStationState();

	// FUNCTION: LEGO1 0x100061d0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0174
		return "GasStationState";
	}

	// FUNCTION: LEGO1 0x100061e0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, GasStationState::ClassName()) || LegoState::IsA(p_name);
	}

private:
	undefined4 m_unk0x08[3];
	undefined4 m_unk0x14;
	undefined2 m_unk0x18;
	undefined2 m_unk0x1a;
	undefined2 m_unk0x1c;
	undefined2 m_unk0x1e;
	undefined2 m_unk0x20;
};

#endif // GASSTATIONSTATE_H
