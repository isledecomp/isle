#ifndef LEGOACTOR_H
#define LEGOACTOR_H

#include "decomp.h"
#include "legoentity.h"

// VTABLE 0x100d6d68
// SIZE 0x78
class LegoActor : public LegoEntity {
public:
	LegoActor();

	// OFFSET: LEGO1 0x1002d210
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f0124
		return "LegoActor";
	}

	// OFFSET: LEGO1 0x1002d220
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoActor::ClassName()) || LegoEntity::IsA(name);
	}

	virtual void VTable0x50(); // vtable+0x50
	virtual void VTable0x54(); // vtable+0x54
	virtual void VTable0x58(); // vtable+0x58
	virtual void VTable0x5c(); // vtable+0x5c
	virtual void VTable0x60(); // vtable+0x60
	virtual void VTable0x64(); // vtable+0x64

private:
	undefined unk68[0x10];
};

#endif // LEGOACTOR_H
