#ifndef ELEVATORBOTTOM_H
#define ELEVATORBOTTOM_H

#include "decomp.h"
#include "legogamestate.h"
#include "legoworld.h"

class LegoControlManagerNotificationParam;

// VTABLE: LEGO1 0x100d5f20
// VTABLE: BETA10 0x101b96f0
// SIZE 0xfc
class ElevatorBottom : public LegoWorld {
public:
	ElevatorBottom();
	~ElevatorBottom() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10017f10
	MxBool EnabledAfterDestruction() override { return TRUE; } // vtable+0x5c

	// FUNCTION: LEGO1 0x10017f20
	// FUNCTION: BETA10 0x10028130
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04ac
		return "ElevatorBottom";
	}

	// FUNCTION: LEGO1 0x10017f30
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ElevatorBottom::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool Escape() override;                         // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	// SYNTHETIC: LEGO1 0x10018040
	// ElevatorBottom::`scalar deleting destructor'

private:
	LegoGameState::Area m_destLocation; // 0xf8

	MxLong HandleControl(LegoControlManagerNotificationParam& p_param);
};

#endif // ELEVATORBOTTOM_H
