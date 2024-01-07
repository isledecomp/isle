#ifndef SKATEBOARD_H
#define SKATEBOARD_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d55f0
// SIZE 0x168
class SkateBoard : public IslePathActor {
public:
	SkateBoard();

	// FUNCTION: LEGO1 0x1000fdd0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f041c
		return "SkateBoard";
	}

	// FUNCTION: LEGO1 0x1000fde0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, SkateBoard::ClassName()) || IslePathActor::IsA(p_name);
	}

private:
	// TODO: SkateBoard types
	undefined m_unk0x160;
	undefined m_unk0x161[0x7];
};

#endif // SKATEBOARD_H
