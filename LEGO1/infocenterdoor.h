#ifndef INFOCENTERDOOR_H
#define INFOCENTERDOOR_H

#include "legoworld.h"

// VTABLE: LEGO1 0x100d72d8
// SIZE 0xfc
class InfocenterDoor : public LegoWorld {
public:
	InfocenterDoor();
	virtual ~InfocenterDoor(); // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4

	// FUNCTION: LEGO1 0x100377b0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f049c
		return "InfocenterDoor";
	}

	// FUNCTION: LEGO1 0x100377c0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, InfocenterDoor::ClassName()) || LegoWorld::IsA(p_name);
	}
};

#endif // INFOCENTERDOOR_H
