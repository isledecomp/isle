#ifndef HELICOPTERSTATE_H
#define HELICOPTERSTATE_H

#include "decomp.h"
#include "legostate.h"

// VTABLE: LEGO1 0x100d5418
// SIZE 0xc
class HelicopterState : public LegoState {
public:
	// FUNCTION: LEGO1 0x1000e0d0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0144
		return "HelicopterState";
	}

	// FUNCTION: LEGO1 0x1000e0e0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, HelicopterState::ClassName()) || LegoState::IsA(p_name);
	}

	inline void SetUnknown8(MxU32 p_unk0x8) { m_unk0x8 = p_unk0x8; }
	inline MxU32 GetUnkown8() { return m_unk0x8; }

protected:
	MxU32 m_unk0x8; // 0x8
};

#endif // HELICOPTERSTATE_H
