#ifndef ELEVATORBOTTOM_H
#define ELEVATORBOTTOM_H

#include "decomp.h"
#include "legogamestate.h"
#include "legoworld.h"

class LegoControlManagerEvent;

// VTABLE: LEGO1 0x100d5f20
// SIZE: 0xfc (from inlined ctor at 0x1000a8aa)
class ElevatorBottom : public LegoWorld {
public:
	ElevatorBottom();
	~ElevatorBottom() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x10017f20
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04ac
		return "ElevatorBottom";
	}

	// FUNCTION: LEGO1 0x10017f30
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ElevatorBottom::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50

	// FUNCTION: LEGO1 0x10017f10
	MxBool VTable0x5c() override { return TRUE; } // vtable+0x5c

	MxBool VTable0x64() override;          // vtable+0x64
	void Enable(MxBool p_enable) override; // vtable+0x68

	// SYNTHETIC: LEGO1 0x10018040
	// ElevatorBottom::`scalar deleting destructor'

private:
	LegoGameState::Area m_destLocation; // 0xf8

	MxLong HandleClick(LegoControlManagerEvent& p_param);
};

#endif // ELEVATORBOTTOM_H
