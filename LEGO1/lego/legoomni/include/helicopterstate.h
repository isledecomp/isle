#ifndef HELICOPTERSTATE_H
#define HELICOPTERSTATE_H

#include "decomp.h"
#include "legostate.h"

// VTABLE: LEGO1 0x100d5418
// SIZE 0x0c
class HelicopterState : public LegoState {
public:
	// FUNCTION: LEGO1 0x1000e0d0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0144
		return "HelicopterState";
	}

	// FUNCTION: LEGO1 0x1000e0e0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, HelicopterState::ClassName()) || LegoState::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x1000e0b0
	MxBool VTable0x14() override { return FALSE; } // vtable+0x14

	// FUNCTION: LEGO1 0x1000e0c0
	MxBool SetFlag() override
	{
		m_unk0x08 = 0;
		return TRUE;
	} // vtable+0x18

	inline void SetUnknown8(MxU32 p_unk0x08) { m_unk0x08 = p_unk0x08; }
	inline MxU32 GetUnkown8() { return m_unk0x08; }

	// SYNTHETIC: LEGO1 0x1000e190
	// HelicopterState::`scalar deleting destructor'

protected:
	MxU32 m_unk0x08; // 0x08
};

#endif // HELICOPTERSTATE_H
