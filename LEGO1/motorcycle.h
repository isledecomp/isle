#ifndef MOTORCYCLE_H
#define MOTORCYCLE_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d7090
// SIZE 0x16c
class Motorcycle : public IslePathActor {
public:
	Motorcycle();

	// FUNCTION: LEGO1 0x10035840
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f38e8
		return "Motorcycle";
	}

	// FUNCTION: LEGO1 0x10035850
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Motorcycle::ClassName()) || IslePathActor::IsA(p_name);
	}

private:
	undefined m_unk0x160[4];
	MxFloat m_unk0x164;
	undefined m_unk0x168[4];
};

#endif // MOTORCYCLE_H
