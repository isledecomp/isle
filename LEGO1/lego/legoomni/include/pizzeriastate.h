#ifndef PIZZERIASTATE_H
#define PIZZERIASTATE_H

#include "legostate.h"

// SIZE 0x14
struct PizzeriaStateStruct {
	undefined4 m_unk0x00; // 0x00
	undefined4 m_unk0x04; // 0x04
	undefined4 m_unk0x08; // 0x08
	undefined4 m_unk0x0c; // 0x0c
	undefined4 m_unk0x10; // 0x10
};

// VTABLE: LEGO1 0x100d5ee8
// SIZE 0x58
class PizzeriaState : public LegoState {
public:
	PizzeriaState();

	// FUNCTION: LEGO1 0x10017c20
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0370
		return "PizzeriaState";
	}

	// FUNCTION: LEGO1 0x10017c30
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PizzeriaState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult VTable0x1c(LegoFile* p_legoFile) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10017ce0
	// PizzeriaState::`scalar deleting destructor'

private:
	Playlist m_unk0x08[5];         // 0x08
	PizzeriaStateStruct m_unk0x44; // 0x44
};

#endif // PIZZERIASTATE_H
