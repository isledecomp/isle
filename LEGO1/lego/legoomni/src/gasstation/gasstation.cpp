#include "gasstation.h"

#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"

// GLOBAL: LEGO1 0x100f0160
undefined4 g_unk0x100f0160 = 3;

// FUNCTION: LEGO1 0x100046a0
GasStation::GasStation()
{
	m_unk0xf8 = 0;
	m_state = NULL;
	m_transitionDestination = LegoGameState::e_noArea;
	m_unk0x108 = 0;
	m_unk0x104 = 0;
	m_unk0x114 = 0;
	m_unk0x106 = 0;
	m_unk0x10c = 0;
	m_unk0x115 = 0;
	m_unk0x110 = 0;

	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10004770
MxBool GasStation::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x100048c0
GasStation::~GasStation()
{
	InputManager()->UnRegister(this);
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	ControlManager()->Unregister(this);
	TickleManager()->UnregisterClient(this);
	NotificationManager()->Unregister(this);
	g_unk0x100f0160 = 3;
}

// FUNCTION: LEGO1 0x10004990
MxResult GasStation::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	InputManager()->SetCamera(NULL);

	m_state = (GasStationState*) GameState()->GetState("GasStationState");
	if (!m_state) {
		m_state = (GasStationState*) GameState()->CreateState("GasStationState");
		m_state->GetUnknown0x14().SetUnknown0x00(1);
	}
	else {
		GasStationState::Unknown0x14& unk0x14 = m_state->GetUnknown0x14();
		if (unk0x14.GetUnknown0x00() == 4) {
			unk0x14.SetUnknown0x00(4);
		}
		else {
			unk0x14.SetUnknown0x00(3);
		}
	}

	GameState()->SetCurrentArea(LegoGameState::e_garage);
	GameState()->StopArea(LegoGameState::e_previousArea);

	InputManager()->Register(this);
	SetIsWorldActive(FALSE);
	return result;
}

// FUNCTION: LEGO1 0x10004a60
MxLong GasStation::Notify(MxParam& p_param)
{
	MxResult result = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetNotification()) {
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationKeyPress:
			result = HandleKeyPress((((LegoEventNotificationParam&) p_param)).GetKey());
			break;
		case c_notificationButtonDown:
			result = HandleButtonDown(((LegoControlManagerEvent&) p_param));
			break;
		case c_notificationClick:
			result = HandleClick((LegoControlManagerEvent&) p_param);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(m_transitionDestination);
			break;
		}
	}

	return result;
}

// STUB: LEGO1 0x10004b30
void GasStation::ReadyWorld()
{
	// TODO
}

// STUB: LEGO1 0x10005660
MxLong GasStation::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10005920
MxLong GasStation::HandleKeyPress(MxS8 p_key)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10005960
MxLong GasStation::HandleButtonDown(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10005b20
MxLong GasStation::HandleClick(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10005c40
void GasStation::Enable(MxBool p_enable)
{
	LegoWorld::Enable(p_enable);

	if (p_enable) {
		InputManager()->SetWorld(this);
		InputManager()->SetCamera(NULL);
	}
	else {
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}
	}
}

// STUB: LEGO1 0x10005c90
MxResult GasStation::Tickle()
{
	// TODO

	return SUCCESS;
}

// STUB: LEGO1 0x10005e70
MxBool GasStation::VTable0x64()
{
	// TODO
	return FALSE;
}
