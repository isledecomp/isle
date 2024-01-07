#ifndef ACT3STATE_H
#define ACT3STATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d4fc8
// SIZE 0xc
class Act3State : public LegoState {
public:
	inline Act3State() { m_unk0x08 = 0; }

	// FUNCTION: LEGO1 0x1000e300
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03f0
		return "Act3State";
	}

	// FUNCTION: LEGO1 0x1000e310
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act3State::ClassName()) || LegoState::IsA(p_name);
	}

	virtual MxBool VTable0x14() override;

private:
	// FIXME: May be part of LegoState? Uncertain...
	MxU32 m_unk0x08;
};

#endif // ACT3STATE_H
