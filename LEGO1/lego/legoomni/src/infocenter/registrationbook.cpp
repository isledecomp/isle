#include "registrationbook.h"

#include "infocenterstate.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(RegistrationBook, 0x2d0)

// FUNCTION: LEGO1 0x10076d20
RegistrationBook::RegistrationBook() : m_unk0xf8(0x80000000), m_unk0xfc(1)
{
	memset(m_unk0x100, 0, sizeof(m_unk0x100));
	memset(m_unk0x168, 0, sizeof(m_unk0x168));

	// Maybe not be part of the struct, but then it would need packing
	m_unk0x280.m_unk0x0e = 0;

	memset(m_unk0x290, 0, sizeof(m_unk0x290));
	memset(&m_unk0x280, -1, sizeof(m_unk0x280) - 2);

	m_unk0x2b8 = 0;
	m_infocenterState = NULL;

	NotificationManager()->Register(this);

	m_unk0x2c1 = 0;
	m_unk0x2c4 = 0;
	m_unk0x2c8 = 0;
	m_unk0x2cc = 0;
}

// STUB: LEGO1 0x10076f50
RegistrationBook::~RegistrationBook()
{
	// TODO
}

// FUNCTION: LEGO1 0x10077060
MxResult RegistrationBook::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
		SetIsWorldActive(FALSE);
		InputManager()->Register(this);

		GameState()->SetCurrentArea(LegoGameState::e_regbook);
		GameState()->StopArea(LegoGameState::e_previousArea);

		m_infocenterState = (InfocenterState*) GameState()->GetState("InfocenterState");
	}
	return result;
}

// FUNCTION: LEGO1 0x100770e0
MxLong RegistrationBook::Notify(MxParam& p_param)
{
	MxLong result = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetType()) {
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationKeyPress:
			m_unk0xf8 = Timer()->GetTime();
			result = HandleKeyPress(((LegoEventNotificationParam&) p_param).GetKey());
			break;
		case c_notificationButtonDown:
			m_unk0xf8 = Timer()->GetTime();
			break;
		case c_notificationClick:
			result = HandleClick((LegoControlManagerEvent&) p_param);
			break;
		case c_notificationType19:
			result = HandleNotification19(p_param);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(LegoGameState::e_infomain);
			break;
		}
	}

	return result;
}

// STUB: LEGO1 0x10077210
MxLong RegistrationBook::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	return 0;
}

// STUB: LEGO1 0x100772d0
MxLong RegistrationBook::HandleKeyPress(MxS8 p_key)
{
	return 0;
}

// STUB: LEGO1 0x100774a0
MxLong RegistrationBook::HandleClick(LegoControlManagerEvent& p_param)
{
	return 0;
}

// STUB: LEGO1 0x10077cc0
void RegistrationBook::ReadyWorld()
{
	// TODO
}

// STUB: LEGO1 0x10077fd0
MxResult RegistrationBook::Tickle()
{
	if (!m_worldStarted) {
		LegoWorld::Tickle();
	}
	else {
		// TODO
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10078180
void RegistrationBook::Enable(MxBool p_enable)
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

// STUB: LEGO1 0x100781d0
MxLong RegistrationBook::HandleNotification19(MxParam& p_param)
{
	return 0;
}

// FUNCTION: LEGO1 0x100783e0
MxBool RegistrationBook::VTable0x64()
{
	DeleteObjects(&m_atom, 500, 506);
	return TRUE;
}
