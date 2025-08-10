#ifndef INFOCENTERDOOR_H
#define INFOCENTERDOOR_H

#include "legogamestate.h"
#include "legoworld.h"

class LegoControlManagerNotificationParam;

// VTABLE: LEGO1 0x100d72d8
// VTABLE: BETA10 0x101b9bc0
// SIZE 0xfc
class InfocenterDoor : public LegoWorld {
public:
	InfocenterDoor();
	~InfocenterDoor() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x100377a0
	MxBool EnabledAfterDestruction() override { return TRUE; } // vtable+0x5c

	// FUNCTION: LEGO1 0x100377b0
	// FUNCTION: BETA10 0x10032790
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f049c
		return "InfocenterDoor";
	}

	// FUNCTION: LEGO1 0x100377c0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, InfocenterDoor::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool Escape() override;                         // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	// SYNTHETIC: LEGO1 0x100378d0
	// InfocenterDoor::`scalar deleting destructor'

private:
	LegoGameState::Area m_destLocation; // 0xf8

	MxLong HandleControl(LegoControlManagerNotificationParam& p_param);
};

#endif // INFOCENTERDOOR_H
