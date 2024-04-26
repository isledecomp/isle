#ifndef PIZZAMISSIONSTATE_H
#define PIZZAMISSIONSTATE_H

#include "legostate.h"

// SIZE 0x20
struct PizzaMissionStateEntry {
public:
	undefined2 m_unk0x00;      // 0x00
	MxU8 m_id;                 // 0x02
	undefined m_unk0x03[0x15]; // 0x03
	MxU16 m_score;             // 0x18
	undefined m_unk0x18[6];    // 0x1a
};

// VTABLE: LEGO1 0x100d7408
// SIZE 0xb0
class PizzaMissionState : public LegoState {
public:
	// FUNCTION: LEGO1 0x10039290
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f00d4
		return "PizzaMissionState";
	}

	// FUNCTION: LEGO1 0x100392a0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PizzaMissionState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoFile* p_legoFile) override; // vtable+0x1c

	inline MxU16 GetScore(MxU8 p_id) { return GetState(p_id)->m_score; }

	// SYNTHETIC: LEGO1 0x10039350
	// PizzaMissionState::`scalar deleting destructor'

private:
	PizzaMissionStateEntry* GetState(MxU8 p_id);

protected:
	undefined4 m_unk0x08;              // 0x08
	undefined4 m_unk0x0c;              // 0x0c
	PizzaMissionStateEntry m_state[5]; // 0x10
};

#endif // PIZZAMISSIONSTATE_H
