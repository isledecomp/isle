#ifndef JUKEBOX_H
#define JUKEBOX_H

#include "legoworld.h"

// VTABLE: LEGO1 0x100d8958
// SIZE 0x104
class JukeBox : public LegoWorld {
public:
	JukeBox();

	// FUNCTION: LEGO1 0x1005d6f0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f02cc
		return "JukeBox";
	}

	// FUNCTION: LEGO1 0x1005d700
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, JukeBox::ClassName()) || LegoWorld::IsA(name);
	}
};

#endif // JUKEBOX_H
