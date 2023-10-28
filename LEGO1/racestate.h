#ifndef RACESTATE_H
#define RACESTATE_H

#include "legostate.h"

struct RaceStateEntry {
public:
	MxU8 m_id;
	undefined m_unk1[1];
	MxU16 m_unk2;
	MxU16 m_color;
};

// VTABLEADDR 0x100d5e30
// SIZE 0x2c
class RaceState : public LegoState {
public:
	RaceState();

	// OFFSET: LEGO1 0x10016010
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f07d0
		return "RaceState";
	}

	// OFFSET: LEGO1 0x10016020
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, RaceState::ClassName()) || LegoState::IsA(name);
	}

	inline MxU16 GetColor(MxU8 id) { return GetState(id)->m_color; }

private:
	RaceStateEntry* GetState(MxU8 id);

protected:
	RaceStateEntry m_state[5];
	undefined2 m_unk26[2];
	undefined4 m_unk28;
};

#endif // RACESTATE_H
