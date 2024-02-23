#ifndef ANIMSTATE_H
#define ANIMSTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d8d80
// SIZE 0x1c
class AnimState : public LegoState {
public:
	AnimState();
	~AnimState() override; // vtable+0x00

	// FUNCTION: LEGO1 0x10065070
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0460
		return "AnimState";
	}

	// FUNCTION: LEGO1 0x10065080
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, AnimState::ClassName()) || LegoState::IsA(p_name);
	}

	MxBool SetFlag() override;                          // vtable+0x18
	MxResult VTable0x1c(LegoFile* p_legoFile) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10065130
	// AnimState::`scalar deleting destructor'

private:
	undefined4 m_unk0x08; // 0x08
	undefined4 m_unk0x0c; // 0x0c
	void* m_unk0x10;      // 0x10
	undefined4 m_unk0x14; // 0x14
	void* m_unk0x18;      // 0x18
};

#endif // ANIMSTATE_H
