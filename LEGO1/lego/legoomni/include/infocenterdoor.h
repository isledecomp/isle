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

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	virtual void VTable0x50() override;                       // vtable+0x50

	// FUNCTION: LEGO1 0x100377a0
	virtual MxBool VTable0x5c() override { return TRUE; } // vtable+0x5c

	virtual MxBool VTable0x64() override;           // vtable+0x64
	virtual void VTable0x68(MxBool p_add) override; // vtable+0x68

	// SYNTHETIC: LEGO1 0x100378d0
	// InfocenterDoor::`scalar deleting destructor'

private:
	MxS32 m_unk0xf8; // 0xf8
};

#endif // INFOCENTERDOOR_H
