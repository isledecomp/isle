#ifndef POLICE_H
#define POLICE_H

#include "decomp.h"
#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"
#include "radio.h"

class LegoControlManagerNotificationParam;
class LegoEventNotificationParam;
class MxDSAction;

// VTABLE: LEGO1 0x100d8af0
// VTABLE: BETA10 0x101bf838
// SIZE 0x10
class PoliceState : public LegoState {
public:
	enum {
		e_noAnimation = 0,
		e_playingAnimation = 1,
	};

	PoliceState();
	~PoliceState() override {}

	// FUNCTION: LEGO1 0x1005e860
	// FUNCTION: BETA10 0x100f0d40
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0444
		return "PoliceState";
	}

	// FUNCTION: LEGO1 0x1005e870
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PoliceState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoStorage* p_storage) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x1005e920
	// PoliceState::`scalar deleting destructor'

	MxS32 GetState() { return m_state; }
	void SetState(MxS32 p_state) { m_state = p_state; }

	void StartAnimation();

	// TODO: Most likely getters/setters are not used according to BETA.

	PoliceScript::Script m_policeScript; // 0x08
	MxS32 m_state;                       // 0x0c
};

// VTABLE: LEGO1 0x100d8a80
// VTABLE: BETA10 0x101bf7c0
// SIZE 0x110
class Police : public LegoWorld {
public:
	Police();
	~Police() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x1005e1d0
	MxBool EnabledAfterDestruction() override { return TRUE; } // vtable+0x5c

	// FUNCTION: LEGO1 0x1005e1e0
	// FUNCTION: BETA10 0x100f0c50
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0450
		return "Police";
	}

	// FUNCTION: LEGO1 0x1005e1f0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Police::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool Escape() override;                         // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	// SYNTHETIC: LEGO1 0x1005e300
	// Police::`scalar deleting destructor'

private:
	MxLong HandleControl(LegoControlManagerNotificationParam& p_param);
	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleKeyPress(LegoEventNotificationParam& p_param);

	Radio m_radio;                      // 0xf8
	PoliceState* m_policeState;         // 0x108
	LegoGameState::Area m_destLocation; // 0x10c
};

#endif // POLICE_H
