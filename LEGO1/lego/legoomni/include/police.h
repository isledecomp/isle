#ifndef POLICE_H
#define POLICE_H

#include "decomp.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoworld.h"
#include "mxdsaction.h"
#include "radio.h"

class PoliceState;

// VTABLE: LEGO1 0x100d8a80
// SIZE 0x110
// Radio at 0xf8
class Police : public LegoWorld {
public:
	Police();
	~Police() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x1005e1e0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0450
		return "Police";
	}

	// FUNCTION: LEGO1 0x1005e1f0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Police::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	MxBool VTable0x64() override;                     // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	// SYNTHETIC: LEGO1 0x1005e300
	// Police::`scalar deleting destructor'

private:
	MxLong HandleClick(LegoControlManagerEvent& p_param);
	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleKeyPress(LegoEventNotificationParam& p_param);

	Radio m_radio;                      // 0xf8
	PoliceState* m_policeState;         // 0x108
	LegoGameState::Area m_destLocation; // 0x10c
};

#endif // POLICE_H
