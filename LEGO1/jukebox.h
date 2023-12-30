#ifndef JUKEBOX_H
#define JUKEBOX_H

#include "decomp.h"
#include "legoworld.h"

// VTABLE: LEGO1 0x100d8958
// SIZE 0x104
class JukeBox : public LegoWorld {
public:
	JukeBox();

	// FUNCTION: LEGO1 0x1005d6f0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f02cc
		return "JukeBox";
	}

	// FUNCTION: LEGO1 0x1005d700
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JukeBox::ClassName()) || LegoWorld::IsA(p_name);
	}

private:
	undefined m_unk0xf8[4]; // 0xf8
	undefined4 m_unk0xfc;   // 0xfc
	undefined2 m_unk0x100;  // 0x100
};

#endif // JUKEBOX_H
