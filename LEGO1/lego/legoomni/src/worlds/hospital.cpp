#include "hospital.h"

#include "hospital_actions.h"
#include "islepathactor.h"
#include "jukebox.h"
#include "jukebox_actions.h"
#include "legocontrolmanager.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "legoutils.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
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
	m_currentActorId = 0;
	m_unk0x100 = 0;
	m_hospitalState = NULL;
	m_unk0x108 = 0;
	m_destLocation = LegoGameState::e_undefined;
	m_unk0x10c = HospitalScript::c__StartUp;
	m_copLedBitmap = NULL;
	m_pizzaLedBitmap = NULL;
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
	MxLong result = 0;
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

// FUNCTION: LEGO1 0x10074a60
void Hospital::ReadyWorld()
{
	PlayMusic(JukeboxScript::c_Hospital_Music);

	m_copLedBitmap = (MxStillPresenter*) Find("MxStillPresenter", "CopLed_Bitmap");
	m_pizzaLedBitmap = (MxStillPresenter*) Find("MxStillPresenter", "PizzaLed_Bitmap");

	if (CurrentActor() == NULL) {
		m_currentActorId = 5;
	}
	else {
		m_currentActorId = CurrentActor()->GetActorId();
	}

	switch (m_currentActorId) {
	case 1:
		m_hospitalState->m_unk0x0c = m_hospitalState->m_unk0x0e;

		if (m_hospitalState->m_unk0x0e < 5) {
			m_hospitalState->m_unk0x0e += 1;
		}

		break;
	case 2:
		m_hospitalState->m_unk0x0c = m_hospitalState->m_unk0x10;

		if (m_hospitalState->m_unk0x10 < 5) {
			m_hospitalState->m_unk0x10 += 1;
		}

		break;
	case 3:
		m_hospitalState->m_unk0x0c = m_hospitalState->m_unk0x12;

		if (m_hospitalState->m_unk0x12 < 5) {
			m_hospitalState->m_unk0x12 += 1;
		}

		break;
	case 4:
		m_hospitalState->m_unk0x0c = m_hospitalState->m_unk0x14;

		if (m_hospitalState->m_unk0x14 < 5) {
			m_hospitalState->m_unk0x14 += 1;
		}

		break;
	case 5:
		m_hospitalState->m_unk0x0c = m_hospitalState->m_unk0x16;

		if (m_hospitalState->m_unk0x16 < 5) {
			m_hospitalState->m_unk0x16 += 1;
		}

		break;
	}

	if (m_hospitalState->m_unk0x0c < 3) {
		HospitalScript::Script hospitalScript[] = {
			HospitalScript::c_hho002cl_RunAnim,
			HospitalScript::c_hho004jk_RunAnim,
			HospitalScript::c_hho007p1_RunAnim
		};

		m_hospitalState->m_unk0x08.m_unk0x00 = 5;

		PlayAction(hospitalScript[m_hospitalState->m_unk0x0c]);
		m_unk0x10c = hospitalScript[m_hospitalState->m_unk0x0c];
	}
	else {
		m_unk0x100 = 1;
		m_unk0x124 = Timer()->GetTime();

		m_hospitalState->m_unk0x08.m_unk0x00 = 6;

		PlayAction(HospitalScript::c_hho003cl_RunAnim);
		m_unk0x10c = HospitalScript::c_hho003cl_RunAnim;
	}

	m_unk0x108 = 1;

	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x10074dd0
MxLong Hospital::HandleKeyPress(MxS8 p_key)
{
	MxLong result = 0;

	if (p_key == ' ' && g_unk0x100f7918 == 0) {
		DeleteObjects(&m_atom, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
		result = 1;
	}

	return result;
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

inline void Hospital::PlayAction(MxU32 p_objectId)
{
	MxDSAction action;
	action.SetAtomId(*g_hospitalScript);
	action.SetObjectId(p_objectId);

	BackgroundAudioManager()->LowerVolume();
	Start(&action);
}

// FUNCTION: LEGO1 0x10076270
MxResult Hospital::Tickle()
{
	if (!m_worldStarted) {
		LegoWorld::Tickle();
		return SUCCESS;
	}

	if (g_unk0x100f7918 != 0) {
		g_unk0x100f7918 -= 1;
	}

	MxLong time = Timer()->GetTime();

	if (m_unk0x118 != 0) {
		if (time - m_unk0x11c > 300) {
			m_unk0x11c = time;
			g_unk0x100f791c = !g_unk0x100f791c;
			m_copLedBitmap->Enable(g_unk0x100f791c);
		}

		if (time - m_unk0x120 > 200) {
			m_unk0x120 = time;
			g_unk0x100f7920 = !g_unk0x100f7920;
			m_pizzaLedBitmap->Enable(g_unk0x100f7920);
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
