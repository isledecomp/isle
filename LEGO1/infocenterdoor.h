#ifndef INFOCENTERDOOR_H
#define INFOCENTERDOOR_H

#include "legoworld.h"

// VTABLEADDR 0x100d72d8
// SIZE 0xfc
class InfocenterDoor : public LegoWorld {
public:
	InfocenterDoor();
	virtual ~InfocenterDoor(); // vtable+0x0

	virtual MxLong Notify(MxParam& p) override; // vtable+0x4

	// OFFSET: LEGO1 0x100377b0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f049c
		return "InfocenterDoor";
	}

	// OFFSET: LEGO1 0x100377c0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, InfocenterDoor::ClassName()) || LegoWorld::IsA(name);
	}
};

#endif // INFOCENTERDOOR_H
