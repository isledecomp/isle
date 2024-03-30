#ifndef LEGOACT2STATE_H
#define LEGOACT2STATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d4a70
// SIZE 0x10
class LegoAct2State : public LegoState {
public:
	~LegoAct2State() override {}

	// FUNCTION: LEGO1 0x1000df80
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0428
		return "LegoAct2State";
	}

	// FUNCTION: LEGO1 0x1000df90
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAct2State::ClassName()) || LegoState::IsA(p_name);
	}

	MxBool VTable0x14() override; // vtable+0x14

	// SYNTHETIC: LEGO1 0x1000e040
	// LegoAct2State::`scalar deleting destructor'

	inline undefined4 GetUnknown0x08() { return m_unk0x08; }
	inline void SetUnknown0x0c(undefined p_unk0x0c) { m_unk0x0c = p_unk0x0c; }

private:
	undefined4 m_unk0x08; // 0x08
	undefined m_unk0x0c;  // 0x0c
};

#endif // LEGOACT2STATE_H
