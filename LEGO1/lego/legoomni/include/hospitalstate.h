#ifndef HOSPITALSTATE_H
#define HOSPITALSTATE_H

#include "decomp.h"
#include "legostate.h"

// VTABLE: LEGO1 0x100d97a0
// SIZE 0x18
class HospitalState : public LegoState {
public:
	// SIZE 0x04
	struct Unknown0x08 {
		undefined4 m_unk0x00; // 0x00
	};

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

	friend class Hospital;

private:
	Unknown0x08 m_unk0x08; // 0x08
	MxS16 m_unk0x0c;       // 0x0c
	MxS16 m_unk0x0e;       // 0x0e
	MxS16 m_unk0x10;       // 0x10
	MxS16 m_unk0x12;       // 0x12
	MxS16 m_unk0x14;       // 0x14
	MxS16 m_unk0x16;       // 0x16
};

#endif // HOSPITALSTATE_H
