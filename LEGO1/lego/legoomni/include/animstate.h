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
		// STRING: LEGO1 0x100f0460
		return "AnimState";
	}

	// FUNCTION: LEGO1 0x10065080
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, AnimState::ClassName()) || LegoState::IsA(p_name);
	}

	virtual MxBool SetFlag() override;                                      // vtable+0x18
	virtual MxResult VTable0x1c(LegoFileStream* p_legoFileStream) override; // vtable+0x1C

	// SYNTHETIC: LEGO1 0x10065130
	// AnimState::`scalar deleting destructor'

private:
	undefined4 m_unk0x8;
	undefined4 m_unk0xc;
	void* m_unk0x10;
	undefined4 m_unk0x14;
	void* m_unk0x18;
};

#endif // ANIMSTATE_H
