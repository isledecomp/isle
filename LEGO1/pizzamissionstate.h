#ifndef PIZZAMISSIONSTATE_H
#define PIZZAMISSIONSTATE_H

#include "legostate.h"

struct PizzaMissionStateEntry {
public:
	undefined2 m_unk0;
	MxU8 m_id;
	undefined m_unk3[0x15];
	MxU16 m_color;
	undefined m_unk18[6];
};

// VTABLE: LEGO1 0x100d7408
class PizzaMissionState : public LegoState {
public:
	// FUNCTION: LEGO1 0x10039290
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f00d4
		return "PizzaMissionState";
	}

	// FUNCTION: LEGO1 0x100392a0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PizzaMissionState::ClassName()) || LegoState::IsA(p_name);
	}

	inline MxU16 GetColor(MxU8 id) { return GetState(id)->m_color; }

private:
	PizzaMissionStateEntry* GetState(MxU8 id);

protected:
	undefined4 m_unk8;
	undefined4 m_unkc;
	PizzaMissionStateEntry m_state[5];
};

#endif // PIZZAMISSIONSTATE_H
