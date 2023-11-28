#ifndef AMBULANCE_H
#define AMBULANCE_H

#include "islepathactor.h"

// VTABLE: LEGO1 0x100d71a8
// SIZE 0x184
class Ambulance : public IslePathActor {
public:
	Ambulance();

	// FUNCTION: LEGO1 0x10035fa0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f03c4
		return "Ambulance";
	}

	// FUNCTION: LEGO1 0x10035fb0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, Ambulance::ClassName()) || IslePathActor::IsA(name);
	}

private:
	// TODO: Ambulance fields
	undefined m_unk160[4];
	MxS32 m_unk164;
	MxS16 m_unk168;
	MxS16 m_unk16a;
	MxS16 m_unk16c;
	MxS16 m_unk16e;
	MxS16 m_unk170;
	MxS16 m_unk172;
	MxS32 m_unk174;
	MxS32 m_unk178;
	MxFloat m_unk17c;
	undefined m_unk180[4];
};

#endif // AMBULANCE_H
