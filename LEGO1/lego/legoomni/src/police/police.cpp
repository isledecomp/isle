#include "police.h"

#include "jukebox.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(Police, 0x110)

// FUNCTION: LEGO1 0x1005e130
Police::Police()
{
	m_policeState = NULL;
	m_transitionDestination = 0;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x1005e1d0
MxBool Police::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x1005e320
Police::~Police()
{
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	ControlManager()->Unregister(this);
	InputManager()->UnRegister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x1005e3e0
MxResult Police::Create(MxDSAction& p_dsAction)
{
	MxResult ret = LegoWorld::Create(p_dsAction);
	if (ret == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	SetIsWorldActive(FALSE);
	InputManager()->Register(this);

	LegoGameState* gameState = GameState();
	PoliceState* policeState = (PoliceState*) gameState->GetState("PoliceState");
	if (!policeState) {
		policeState = (PoliceState*) gameState->CreateState("PoliceState");
	}

	m_policeState = policeState;
	GameState()->SetCurrentArea(0x22);
	GameState()->StopArea();
	return ret;
}

// FUNCTION: LEGO1 0x1005e480
MxLong Police::Notify(MxParam& p_param)
{
	MxLong result = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetNotification()) {
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationKeyPress:
			result = HandleKeyPress(((LegoEventNotificationParam&) p_param));
			break;
		case c_notificationType11:
			result = HandleNotification11((MxNotificationParam&) p_param);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(m_transitionDestination);
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1005e530
void Police::ReadyWorld()
{
	LegoWorld::ReadyWorld();
	PlayMusic(JukeBox::e_policeStation);
	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// STUB: LEGO1 0x1005e550
MxLong Police::HandleNotification11(MxNotificationParam& p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x1005e6a0
MxLong Police::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	MxDSAction* action = p_param.GetAction();

	if (m_radio.Notify(p_param) == 0 && m_atom == action->GetAtomId()) {
		if (m_policeState->GetUnknown0x0c() == 1) {
			m_policeState->SetUnknown0x0c(0);
			return 1;
		}

		return 0;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1005e6f0
MxLong Police::HandleKeyPress(LegoEventNotificationParam& p_param)
{
	MxLong result = 0;

	if (p_param.GetKey() == ' ' && m_policeState->GetUnknown0x0c() == 1) {
		DeleteObjects(&m_atom, 500, 501);
		m_policeState->SetUnknown0x0c(0);
		return 1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1005e740
void Police::Enable(MxBool p_enable)
{
	LegoWorld::Enable(p_enable);

	if (p_enable) {
		InputManager()->SetWorld(this);
		SetIsWorldActive(FALSE);
	}
	else {
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}
	}
}

// FUNCTION: LEGO1 0x1005e790
MxBool Police::VTable0x64()
{
	DeleteObjects(&m_atom, 500, 510);
	m_transitionDestination = 2;
	return TRUE;
}
