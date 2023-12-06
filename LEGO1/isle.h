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
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, Isle::ClassName()) || LegoWorld::IsA(name);
	}

	inline void setUnknown13c(MxU32 p) { m_unk13c = p; }

protected:
	undefined m_unkf8[0x44];
	MxU32 m_unk13c;
};

#endif // ISLE_H
