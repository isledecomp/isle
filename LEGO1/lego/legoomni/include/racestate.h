#ifndef RACESTATE_H
#define RACESTATE_H

#include "legostate.h"

struct RaceStateEntry {
public:
	MxU8 m_id;
	undefined m_unk0x01[1];
	MxU16 m_unk0x02;
	MxU16 m_color;
};

// VTABLE: LEGO1 0x100d5e30
// SIZE 0x2c
class RaceState : public LegoState {
public:
	RaceState();

	// FUNCTION: LEGO1 0x10016010
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f07d0
		return "RaceState";
	}

	// FUNCTION: LEGO1 0x10016020
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RaceState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult VTable0x1c(LegoFile* p_legoFile) override; // vtable+0x1c

	inline MxU16 GetColor(MxU8 p_id) { return GetState(p_id)->m_color; }

	// SYNTHETIC: LEGO1 0x1000f6f0
	// RaceState::~RaceState

	// SYNTHETIC: LEGO1 0x100160d0
	// RaceState::`scalar deleting destructor'

private:
	RaceStateEntry* GetState(MxU8 p_id);

protected:
	RaceStateEntry m_state[5]; // 0x08
	undefined2 m_unk0x26[2];   // 0x26
	undefined4 m_unk0x28;      // 0x28
};

#endif // RACESTATE_H
