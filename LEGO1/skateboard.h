#ifndef SKATEBOARD_H
#define SKATEBOARD_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLEADDR 0x100d55f0
// SIZE 0x168
class SkateBoard : public IslePathActor {
public:
	SkateBoard();

	// OFFSET: LEGO1 0x1000fdd0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f041c
		return "SkateBoard";
	}

	// OFFSET: LEGO1 0x1000fde0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, SkateBoard::ClassName()) || IslePathActor::IsA(name);
	}

private:
	// TODO: SkateBoard types
	undefined m_unk160;
	undefined m_unk161[0x7];
};

#endif // SKATEBOARD_H
