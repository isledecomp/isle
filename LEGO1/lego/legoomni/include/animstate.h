#ifndef ANIMSTATE_H
#define ANIMSTATE_H

#include "legostate.h"

// SIZE 0x30
struct ModelInfo {
	char* m_modelName;    // 0x00
	MxU8 m_unk0x04;       // 0x04
	float m_location[3];  // 0x08
	float m_direction[3]; // 0x14
	float m_up[3];        // 0x20
	MxU8 m_unk0x2c;       // 0x2c
};

// SIZE 0x30
struct AnimInfo {
	char* m_animName;     // 0x00
	undefined4 m_unk0x04; // 0x04
	MxS16 m_unk0x08;      // 0x08
	MxU8 m_unk0x0a;       // 0x0a
	MxU8 m_unk0x0b;       // 0x0b
	MxU8 m_unk0x0c;       // 0x0c
	MxU8 m_unk0x0d;       // 0x0d
	MxU32 m_unk0x10[4];   // 0x10
	MxU8 m_modelCount;    // 0x20
	ModelInfo* m_models;  // 0x24
	MxU8 m_unk0x28;       // 0x28
	MxU8 m_unk0x29;       // 0x29
	MxS8 m_unk0x2a[3];    // 0x2a
};

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

	void FUN_100651d0(MxU32, AnimInfo*, MxU32&);
	void FUN_10065240(MxU32, AnimInfo*, MxU32);

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
