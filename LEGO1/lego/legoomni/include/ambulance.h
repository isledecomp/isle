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
		// STRING: LEGO1 0x100f03c4
		return "Ambulance";
	}

	// FUNCTION: LEGO1 0x10035fb0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Ambulance::ClassName()) || IslePathActor::IsA(p_name);
	}

private:
	// TODO: Ambulance fields
	undefined m_unk0x160[4];
	MxS32 m_unk0x164;
	MxS16 m_unk0x168;
	MxS16 m_unk0x16a;
	MxS16 m_unk0x16c;
	MxS16 m_unk0x16e;
	MxS16 m_unk0x170;
	MxS16 m_unk0x172;
	MxS32 m_unk0x174;
	MxS32 m_unk0x178;
	MxFloat m_unk0x17c;
	undefined m_unk0x180[4];
};

#endif // AMBULANCE_H
