#include "hospital.h"

#include "legocontrolmanager.h"
#include "legoinputmanager.h"
#include "legoutils.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(Hospital, 0x12c)

// GLOBAL: LEGO1 0x100f7918
undefined4 g_unk0x100f7918 = 3;

// GLOBAL: LEGO1 0x100f791c
undefined g_unk0x100f791c = 0;

// GLOBAL: LEGO1 0x100f7920
undefined g_unk0x100f7920 = 0;

// FUNCTION: LEGO1 0x100745e0
Hospital::Hospital()
{
	m_unk0xf8 = 0;
	m_unk0x100 = 0;
	m_hospitalState = NULL;
	m_unk0x108 = 0;
	m_destLocation = LegoGameState::e_undefined;
	m_unk0x10c = 0;
	m_unk0x110 = 0;
	m_unk0x114 = 0;
	m_unk0x118 = 0;
	m_unk0x11c = 0;
	m_unk0x120 = 0;
	m_unk0x128 = 0;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x100746a0
MxBool Hospital::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x100747f0
Hospital::~Hospital()
{
	InputManager()->UnRegister(this);
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	ControlManager()->Unregister(this);
	TickleManager()->UnregisterClient(this);

	m_hospitalState->m_unk0x08.m_unk0x00 = 3;

	NotificationManager()->Unregister(this);
	g_unk0x100f7918 = 3;
}

// FUNCTION: LEGO1 0x100748c0
MxResult Hospital::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	SetIsWorldActive(FALSE);

	m_hospitalState = (HospitalState*) GameState()->GetState("HospitalState");
	if (!m_hospitalState) {
		m_hospitalState = (HospitalState*) GameState()->CreateState("HospitalState");
		m_hospitalState->m_unk0x08.m_unk0x00 = 1;
	}
	else if (m_hospitalState->m_unk0x08.m_unk0x00 == 4) {
		m_hospitalState->m_unk0x08.m_unk0x00 = 4;
	}
	else {
		m_hospitalState->m_unk0x08.m_unk0x00 = 3;
	}

	GameState()->SetCurrentArea(LegoGameState::e_hospital);
	GameState()->StopArea(LegoGameState::e_previousArea);

	InputManager()->Register(this);
	FUN_1003ef00(FALSE);

	return result;
}

// FUNCTION: LEGO1 0x10074990
MxLong Hospital::Notify(MxParam& p_param)
{
	MxResult result = SUCCESS;
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
			if (m_destLocation != LegoGameState::e_undefined) {
				GameState()->SwitchArea(m_destLocation);
			}
			break;
		}
	}

	return result;
}

// STUB: LEGO1 0x10074a60
void Hospital::ReadyWorld()
{
	// TODO
}

// STUB: LEGO1 0x10074dd0
MxLong Hospital::HandleKeyPress(MxS8 p_key)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10074e00
MxLong Hospital::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10075710
MxLong Hospital::HandleButtonDown(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10075f90
MxBool Hospital::HandleClick(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10076220
void Hospital::Enable(MxBool p_enable)
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

// FUNCTION: LEGO1 0x10076270
MxResult Hospital::Tickle()
{
	if (!m_worldStarted) {
		LegoWorld::Tickle();
		return SUCCESS;
	}
	else {
		if (g_unk0x100f7918 != 0) {
			g_unk0x100f7918 -= 1;
		}

		MxLong time = Timer()->GetTime();

		if (m_unk0x118 != 0) {
			if (300 < (MxLong) (time - m_unk0x11c)) {
				m_unk0x11c = time;
				g_unk0x100f791c = !g_unk0x100f791c;
				m_unk0x110->Enable(g_unk0x100f791c);
			}

			if (200 < (MxLong) (time - m_unk0x120)) {
				m_unk0x120 = time;
				g_unk0x100f7920 = !g_unk0x100f7920;
				m_unk0x114->Enable(g_unk0x100f7920);
			}
		}
	}
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10076330
MxBool Hospital::VTable0x64()
{
	DeleteObjects(&m_atom, HospitalScript::c_hho002cl_RunAnim, 999);
	m_hospitalState->m_unk0x08.m_unk0x00 = 0;

	m_destLocation = LegoGameState::e_infomain;

	return TRUE;
}
