#ifndef ISLE_H
#define ISLE_H

#include "legoworld.h"
#include "radio.h"

// VTABLE: LEGO1 0x100d6fb8
// SIZE 0x140
// Radio at 0x12c
class Isle : public LegoWorld {
public:
	Isle();

	// FUNCTION: LEGO1 0x10030910
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0458
		return "Isle";
	}

	// FUNCTION: LEGO1 0x10030920
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Isle::ClassName()) || LegoWorld::IsA(p_name);
	}
	inline void SetUnknown13c(MxU32 p_unk0x13c) { m_unk0x13c = p_unk0x13c; }

protected:
	undefined4 m_unk0xf8;  // 0xf8
	undefined4 m_unk0xfc;  // 0xfc
	undefined4 m_unk0x100; // 0x100
	undefined4 m_unk0x104; // 0x104
	undefined4 m_unk0x108; // 0x108
	undefined4 m_unk0x10c; // 0x10c
	undefined4 m_unk0x110; // 0x110
	undefined4 m_unk0x114; // 0x114
	undefined4 m_unk0x118; // 0x118
	undefined4 m_unk0x11c; // 0x11c
	undefined4 m_unk0x120; // 0x120
	undefined4 m_unk0x124; // 0x124
	undefined4 m_unk0x128; // 0x128
	Radio m_radio;         // 0x12c
	MxU32 m_unk0x13c;      // 0x13c
};

#endif // ISLE_H
