#ifndef DOORS_H
#define DOORS_H

#include "legopathactor.h"

// VTABLE: LEGO1 0x100d4788
// SIZE 0x1f8
class Doors : public LegoPathActor {
public:
	// FUNCTION: LEGO1 0x1000e430
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03e8
		return "Doors";
	}

	// FUNCTION: LEGO1 0x1000e440
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Doors::ClassName()) || LegoPathActor::IsA(p_name);
	}

	void ParseAction(char*) override;        // vtable+0x20
	void VTable0x70(float p_float) override; // vtable+0x70
	MxS32 VTable0x94() override;             // vtable+0x94

	// SYNTHETIC: LEGO1 0x1000e580
	// Doors::`scalar deleting destructor'

private:
	undefined4 m_unk0x154; // 0x154
	undefined4 m_unk0x158; // 0x158
	undefined4 m_unk0x15c; // 0x15c
	undefined4 m_unk0x160; // 0x160
	MxMatrix m_unk0x164;   // 0x164
	MxMatrix m_unk0x1ac;   // 0x1ac
	undefined4 m_unk0x1f4; // 0x1f4
};

#endif // DOORS_H
