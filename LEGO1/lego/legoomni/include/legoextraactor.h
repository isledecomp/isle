#ifndef LEGOEXTRAACTOR_H
#define LEGOEXTRAACTOR_H

#include "legoanimactor.h"

/*
	VTABLE: LEGO1 0x100d6c00 LegoAnimActor
	VTABLE: LEGO1 0x100d6c10 LegoPathActor
	VTABLE: LEGO1 0x100d6cdc LegoExtraActor
*/
// SIZE 0x1dc
class LegoExtraActor : public virtual LegoAnimActor {
public:
	LegoExtraActor();

	// FUNCTION: LEGO1 0x1002b7a0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f3204
		return "LegoExtraActor";
	}

	// FUNCTION: LEGO1 0x1002b7c0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoExtraActor::ClassName()) || LegoAnimActor::IsA(p_name);
	}

	virtual MxResult FUN_1002aae0();

private:
	undefined4 m_unk0x08; // 0x08
	undefined m_unk0x0c;  // 0x0c
	undefined m_unk0x0d;  // 0x0d
	undefined m_unk0x0e;  // 0x0e
	undefined4 m_unk0x10; // 0x10
	undefined m_unk0x14;  // 0x14
	MxMatrix m_unk0x18;   // 0x18
	undefined4 m_unk0x60; // 0x60
	undefined4 m_unk0x64; // 0x64
};

#endif // LEGOEXTRAACTOR_H
