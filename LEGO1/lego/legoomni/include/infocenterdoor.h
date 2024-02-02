#ifndef INFOCENTERDOOR_H
#define INFOCENTERDOOR_H

#include "legoworld.h"

class LegoControlManagerEvent;

// VTABLE: LEGO1 0x100d72d8
// SIZE 0xfc
class InfocenterDoor : public LegoWorld {
public:
	InfocenterDoor();
	~InfocenterDoor() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x100377b0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f049c
		return "InfocenterDoor";
	}

	// FUNCTION: LEGO1 0x100377c0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, InfocenterDoor::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50

	// FUNCTION: LEGO1 0x100377a0
	MxBool VTable0x5c() override { return TRUE; } // vtable+0x5c

	MxBool VTable0x64() override;          // vtable+0x64
	void Enable(MxBool p_enable) override; // vtable+0x68

	// SYNTHETIC: LEGO1 0x100378d0
	// InfocenterDoor::`scalar deleting destructor'

private:
	MxS32 m_unk0xf8; // 0xf8

	MxLong HandleClick(LegoControlManagerEvent& p_param);
};

#endif // INFOCENTERDOOR_H
