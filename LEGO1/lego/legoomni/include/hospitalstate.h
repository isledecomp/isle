#ifndef HOSPITALSTATE_H
#define HOSPITALSTATE_H

#include "decomp.h"
#include "legostate.h"

// VTABLE: LEGO1 0x100d97a0
// SIZE 0x18
class HospitalState : public LegoState {
public:
	HospitalState();
	~HospitalState() override {}

	// FUNCTION: LEGO1 0x10076400
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0480
		return "HospitalState";
	}

	// FUNCTION: LEGO1 0x10076410
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, HospitalState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult VTable0x1c(LegoFile* p_legoFile) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x100764c0
	// HospitalState::`scalar deleting destructor'

private:
	undefined m_unk0x08[4]; // 0x08
	undefined2 m_unk0x0c;   // 0x0c
	undefined2 m_unk0x0e;   // 0x0e
	undefined2 m_unk0x10;   // 0x10
	undefined2 m_unk0x12;   // 0x12
	undefined2 m_unk0x14;   // 0x14
	undefined2 m_unk0x16;   // 0x16
};

#endif // HOSPITALSTATE_H
