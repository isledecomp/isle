#include "gasstation.h"

#include "garage_actions.h"
#include "islepathactor.h"
#include "jukebox.h"
#include "jukebox_actions.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(GasStation, 0x128)

// GLOBAL: LEGO1 0x100f0160
undefined4 g_unk0x100f0160 = 3;

// FUNCTION: LEGO1 0x100046a0
GasStation::GasStation()
{
	m_currentActorId = 0;
	m_state = NULL;
	m_destLocation = LegoGameState::e_undefined;
	m_trackLedBitmap = NULL;
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
		m_state->m_unk0x14.m_unk0x00 = 1;
	}
	else if (m_state->m_unk0x14.m_unk0x00 == 4) {
		m_state->m_unk0x14.m_unk0x00 = 4;
	}
	else {
		m_state->m_unk0x14.m_unk0x00 = 3;
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
			GameState()->SwitchArea(m_destLocation);
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10004b30
void GasStation::ReadyWorld()
{
	undefined2 comparisonValue;
	PlayMusic(JukeboxScript::c_JBMusic2);

	m_trackLedBitmap = (MxStillPresenter*) Find("MxStillPresenter", "TrackLed_Bitmap");

	m_currentActorId = CurrentActor()->GetActorId();

	switch (m_currentActorId) {
	case 1: {
		switch (m_state->m_unk0x18) {
		case 0:
			m_state->m_unk0x14.m_unk0x00 = 5;
			PlayAction(GarageScript::c_wgs002nu_RunAnim);
			m_unk0x106 = 1;
			break;
		case 1:
			m_state->m_unk0x14.m_unk0x00 = 5;
			PlayAction(GarageScript::c_wgs003nu_RunAnim);
			m_unk0x106 = 1;
			break;
		case 2:
			m_state->m_unk0x14.m_unk0x00 = 5;
			PlayAction(GarageScript::c_wgs004nu_RunAnim);
			m_unk0x106 = 1;
			break;
		default:
			m_state->m_unk0x14.m_unk0x00 = 6;
			PlayAction(GarageScript::c_wgs008nu_RunAnim);
			m_unk0x106 = 1;
			m_unk0x104 = 1;
			break;
		}
		comparisonValue = m_state->m_unk0x18;
		break;
	}
	case 2: {
		switch (m_state->m_unk0x1a) {
		case 0:
			m_state->m_unk0x14.m_unk0x00 = 5;
			PlayAction(GarageScript::c_wgs006nu_RunAnim);
			m_unk0x106 = 1;
			break;
		case 1:
			m_state->m_unk0x14.m_unk0x00 = 5;
			PlayAction(GarageScript::c_wgs007nu_RunAnim);
			m_unk0x106 = 1;
			break;
		default:
			m_state->m_unk0x14.m_unk0x00 = 6;
			PlayAction(GarageScript::c_wgs008nu_RunAnim);
			m_unk0x106 = 1;
			m_unk0x104 = 1;
			break;
		}
		comparisonValue = m_state->m_unk0x1a;
		if (4 < m_state->m_unk0x1a) {
			m_state->m_unk0x1a++;
			return;
		}
		break;
	}
	case 3: {
		switch (m_state->m_unk0x1c) {
		case 0:
			m_state->m_unk0x14.m_unk0x00 = 5;
			PlayAction(GarageScript::c_wgs012nu_RunAnim);
			m_unk0x106 = 1;
			break;
		case 1:
			m_state->m_unk0x14.m_unk0x00 = 5;
			PlayAction(GarageScript::c_wgs014nu_RunAnim);
			m_unk0x106 = 1;
			break;
		default:
			m_state->m_unk0x14.m_unk0x00 = 6;
			FUN_10005590(GarageScript::c_wgs017nu_RunAnim);
			m_unk0x106 = 1;
			m_unk0x104 = 1;
			break;
		}
		if (4 < m_state->m_unk0x1c) {
			m_state->m_unk0x1c++;
			return;
		}
		break;
	}
	case 4: {
		switch (m_state->m_unk0x1e) {
		case 0:
			m_state->m_unk0x14.m_unk0x00 = 5;
			PlayAction(GarageScript::c_wgs009nu_RunAnim);
			m_unk0x106 = 1;
			break;
		case 1:
			m_state->m_unk0x14.m_unk0x00 = 5;
			PlayAction(GarageScript::c_wgs010nu_RunAnim);
			m_unk0x106 = 1;
			break;
		default:
			m_state->m_unk0x14.m_unk0x00 = 6;
			PlayAction(GarageScript::c_wgs008nu_RunAnim);
			m_unk0x106 = 1;
			m_unk0x104 = 1;
			break;
		}
		comparisonValue = m_state->m_unk0x1e;
		break;
	}
	case 5: {
		switch (m_state->m_unk0x20) {
		case 0:
			m_state->m_unk0x14.m_unk0x00 = 5;
			FUN_10005590(GarageScript::c_wgs020nu_RunAnim);
			m_unk0x106 = 1;
			break;
		case 1:
			m_state->m_unk0x14.m_unk0x00 = 5;
			FUN_10005590(GarageScript::c_wgs021nu_RunAnim);
			m_unk0x106 = 1;
			break;
		default:
			m_state->m_unk0x14.m_unk0x00 = 6;
			FUN_10005590(GarageScript::c_wgs022nu_RunAnim);
			m_unk0x106 = 1;
			m_unk0x104 = 1;
			break;
		}
		comparisonValue = m_state->m_unk0x20;
		break;
	}
	default: {
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		return;
	}
	}

	if (comparisonValue < 5) {
		comparisonValue++;
	}

	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x10005590
void GasStation::FUN_10005590(undefined4 p_param)
{
	// TODO
}

inline void GasStation::PlayAction(MxU32 p_objectId)
{
	MxDSAction action;
	action.SetAtomId(*g_garageScript);
	action.SetObjectId(p_objectId);

	BackgroundAudioManager()->LowerVolume();
	Start(&action);
	m_state->FUN_10006430(p_objectId);
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
