#ifndef ISLE_H
#define ISLE_H

#include "legoworld.h"

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
	inline void setUnknown13c(MxU32 p_unk0x13c) { m_unk0x13c = p_unk0x13c; }

protected:
	undefined m_unk0xf8[0x44]; // 0xf8
	MxU32 m_unk0x13c;          // 0x13c
};

#endif // ISLE_H
