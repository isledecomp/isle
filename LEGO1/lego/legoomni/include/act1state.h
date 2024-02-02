#ifndef ACT1STATE_H
#define ACT1STATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d7028
// SIZE 0x26c
class Act1State : public LegoState {
public:
	Act1State();

	// FUNCTION: LEGO1 0x100338a0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0154
		return "Act1State";
	}

	// FUNCTION: LEGO1 0x100338b0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act1State::ClassName()) || LegoState::IsA(p_name);
	}

	MxBool SetFlag() override;                          // vtable+0x18
	MxResult VTable0x1c(LegoFile* p_legoFile) override; // vtable+0x1c

	inline void SetUnknown18(MxU32 p_unk0x18) { m_unk0x18 = p_unk0x18; }
	inline MxU32 GetUnknown18() { return m_unk0x18; }
	inline MxU32 GetUnknown1c() { return m_unk0x1c; }
	inline MxS16 GetUnknown21() { return m_unk0x21; }

	inline void SetUnknown1c(MxU32 p_unk0x1c) { m_unk0x1c = p_unk0x1c; }
	inline void SetUnknown21(MxS16 p_unk0x21) { m_unk0x21 = p_unk0x21; }

	void FUN_10034d00();

	// SYNTHETIC: LEGO1 0x10033960
	// Act1State::`scalar deleting destructor'

protected:
	undefined m_unk0x08[0x10]; // 0x08
	MxU32 m_unk0x18;           // 0x18
	undefined2 m_unk0x1c;      // 0x1c
	undefined m_unk0x1e;       // 0x1e
	undefined m_unk0x1f;       // 0x1f
	undefined m_unk0x20;       // 0x20
	MxBool m_unk0x21;          // 0x21
	undefined m_unk0x22;       // 0x22
							   // TODO
};

#endif // ACT1STATE_H
