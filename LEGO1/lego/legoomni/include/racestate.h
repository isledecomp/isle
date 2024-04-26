#ifndef RACESTATE_H
#define RACESTATE_H

#include "legostate.h"

// SIZE 0x06
struct RaceStateEntry {
public:
	inline MxS16 GetUnknown0x02() { return m_unk0x02; }
	inline MxU16 GetScore() { return m_score; }

	// TODO: Possibly private
	MxU8 m_id;       // 0x00
	MxS16 m_unk0x02; // 0x02
	MxU16 m_score;   // 0x04
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

	MxResult Serialize(LegoFile* p_legoFile) override; // vtable+0x1c

	RaceStateEntry* GetState(MxU8 p_id);

	inline undefined4 GetUnknown0x28() { return m_unk0x28; }

	// SYNTHETIC: LEGO1 0x1000f6f0
	// RaceState::~RaceState

	// SYNTHETIC: LEGO1 0x100160d0
	// RaceState::`scalar deleting destructor'

protected:
	RaceStateEntry m_state[5]; // 0x08
	undefined4 m_unk0x28;      // 0x28
};

#endif // RACESTATE_H
