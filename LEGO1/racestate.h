#ifndef RACESTATE_H
#define RACESTATE_H

#include "legostate.h"

struct RaceStateEntry {
public:
	MxU8 m_id;
	undefined m_unk0x1[1];
	MxU16 m_unk0x2;
	MxU16 m_color;
};

// VTABLE: LEGO1 0x100d5e30
// SIZE 0x2c
class RaceState : public LegoState {
public:
	RaceState();

	// FUNCTION: LEGO1 0x10016010
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07d0
		return "RaceState";
	}

	// FUNCTION: LEGO1 0x10016020
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RaceState::ClassName()) || LegoState::IsA(p_name);
	}

	inline MxU16 GetColor(MxU8 p_id) { return GetState(p_id)->m_color; }

private:
	RaceStateEntry* GetState(MxU8 p_id);

protected:
	RaceStateEntry m_state[5];
	undefined2 m_unk0x26[2];
	undefined4 m_unk0x28;
};

#endif // RACESTATE_H
