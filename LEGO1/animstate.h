#ifndef ANIMSTATE_H
#define ANIMSTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d8d80
// SIZE 0x1c
class AnimState : public LegoState {
public:
	AnimState();
	virtual ~AnimState() override; // vtable+0x0

	// FUNCTION: LEGO1 0x10065070
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0460
		return "AnimState";
	}

	// FUNCTION: LEGO1 0x10065080
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, AnimState::ClassName()) || LegoState::IsA(name);
	}
};

#endif // ANIMSTATE_H
