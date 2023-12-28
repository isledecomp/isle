#ifndef ACT1STATE_H
#define ACT1STATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d7028
// SIZE 0x26c
class Act1State : public LegoState {
public:
	Act1State();

	// FUNCTION: LEGO1 0x100338a0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0154
		return "Act1State";
	};

	// FUNCTION: LEGO1 0x100338b0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act1State::ClassName()) || LegoState::IsA(p_name);
	};

	inline void SetUnknown18(MxU32 p_unk0x18) { m_unk0x18 = p_unk0x18; }
	inline MxU32 GetUnknown18() { return m_unk0x18; }

protected:
	undefined m_unk0x8[0x10]; // 0x8
	MxU32 m_unk0x18;          // 0x18
};

#endif // ACT1STATE_H
