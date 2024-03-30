#ifndef ACT2BRICK_H
#define ACT2BRICK_H

#include "legopathactor.h"

// VTABLE: LEGO1 0x100d9b60
// SIZE 0x194
class Act2Brick : public LegoPathActor {
public:
	Act2Brick();
	~Act2Brick() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x1007a360
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0438
		return "Act2Brick";
	}

	// FUNCTION: LEGO1 0x1007a370
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act2Brick::ClassName()) || LegoEntity::IsA(p_name);
	}

	MxResult VTable0x94(LegoPathActor* p_actor, MxBool p_bool) override; // vtable+0x94

	// SYNTHETIC: LEGO1 0x1007a450
	// Act2Brick::`scalar deleting destructor'

private:
	undefined4 m_unk0x154;      // 0x154
	undefined m_unk0x158[0x0c]; // 0x158
	undefined4 m_unk0x164;      // 0x164
	Mx3DPointFloat m_unk0x168;  // 0x168
	Mx3DPointFloat m_unk0x17c;  // 0x17c
	undefined4 m_unk0x190;      // 0x190
};

#endif // ACT2BRICK_H
