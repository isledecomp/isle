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
		// 0x100f0144
		return "HelicopterState";
	}

	// FUNCTION: LEGO1 0x1000e0e0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, HelicopterState::ClassName()) || LegoState::IsA(name);
	}

	inline void SetUnknown8(undefined4 p_unk8) { m_unk8 = p_unk8; }

protected:
	undefined4 m_unk8;
};

#endif // HELICOPTERSTATE_H
