#ifndef LEGOACTOR_H
#define LEGOACTOR_H

#include "decomp.h"
#include "legoentity.h"

// VTABLE: LEGO1 0x100d6d68
// SIZE 0x78
class LegoActor : public LegoEntity {
public:
	LegoActor();

	// FUNCTION: LEGO1 0x1002d210
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f0124
		return "LegoActor";
	}

	// FUNCTION: LEGO1 0x1002d220
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoActor::ClassName()) || LegoEntity::IsA(p_name);
	}

	virtual MxFloat VTable0x50();             // vtable+0x50
	virtual void VTable0x54(MxFloat p_unk);   // vtable+0x54
	virtual void VTable0x58(MxFloat p_unk);   // vtable+0x58
	virtual MxFloat VTable0x5c();             // vtable+0x5c
	virtual undefined VTable0x60();           // vtable+0x60
	virtual void VTable0x64(undefined p_unk); // vtable+0x64

private:
	MxFloat m_unk0x68;
	undefined4 m_unk0x6c;
	MxFloat m_unk0x70;
	undefined m_unk0x74;
};

#endif // LEGOACTOR_H
