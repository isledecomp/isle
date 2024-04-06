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
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "radio.h"

DECOMP_SIZE_ASSERT(GasStation, 0x128)

// GLOBAL: LEGO1 0x100f0160
undefined4 g_unk0x100f0160 = 3;

// GLOBAL: LEGO1 0x100f0164
MxBool g_trackLedEnabled = FALSE;

// FUNCTION: LEGO1 0x100046a0
GasStation::GasStation()
{
	m_currentActorId = 0;
	m_state = NULL;
	m_destLocation = LegoGameState::e_undefined;
	m_trackLedBitmap = NULL;
	m_unk0x104 = 0;
	m_unk0x114 = FALSE;
	m_unk0x106 = 0;
	m_unk0x10c = 0;
	m_unk0x115 = FALSE;
	m_trackLedTimer = 0;

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
	PlayMusic(JukeboxScript::c_JBMusic2);

	m_trackLedBitmap = (MxStillPresenter*) Find("MxStillPresenter", "TrackLed_Bitmap");
	m_currentActorId = CurrentActor()->GetActorId();

	switch (m_currentActorId) {
	case 1:
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

		if (m_state->m_unk0x18 < 5) {
			m_state->m_unk0x18++;
		}

		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		break;
	case 2:
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

		if (m_state->m_unk0x1a < 5) {
			m_state->m_unk0x1a++;
		}

		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		break;
	case 3:
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
			PlayAction(GarageScript::c_wgs017nu_RunAnim);
			m_unk0x106 = 1;
			m_unk0x104 = 1;
			break;
		}

		if (m_state->m_unk0x1c < 5) {
			m_state->m_unk0x1c++;
		}

		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		break;
	case 4:
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

		if (m_state->m_unk0x1e < 5) {
			m_state->m_unk0x1e++;
		}

		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		break;
	case 5:
		switch (m_state->m_unk0x20) {
		case 0:
			m_state->m_unk0x14.m_unk0x00 = 5;
			PlayAction(GarageScript::c_wgs020nu_RunAnim);
			m_unk0x106 = 1;
			break;
		case 1:
			m_state->m_unk0x14.m_unk0x00 = 5;
			PlayAction(GarageScript::c_wgs021nu_RunAnim);
			m_unk0x106 = 1;
			break;
		default:
			m_state->m_unk0x14.m_unk0x00 = 6;
			PlayAction(GarageScript::c_wgs022nu_RunAnim);
			m_unk0x106 = 1;
			m_unk0x104 = 1;
			break;
		}

		if (m_state->m_unk0x20 < 5) {
			m_state->m_unk0x20++;
		}

		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		break;
	default:
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		break;
	}
}

// FUNCTION: LEGO1 0x10005590
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

// FUNCTION: LEGO1 0x10005920
MxLong GasStation::HandleKeyPress(MxS8 p_key)
{
	if (p_key == ' ' && g_unk0x100f0160 == 0 && this->m_unk0x106 != 0) {
		m_state->FUN_10006490();
		return 1;
	}

	return 0;
}

// STUB: LEGO1 0x10005960
MxLong GasStation::HandleButtonDown(LegoControlManagerEvent& p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x10005b20
MxLong GasStation::HandleClick(LegoControlManagerEvent& p_param)
{
	if (p_param.GetUnknown0x28() == 1) {
		MxDSAction action;

		switch (p_param.GetClickedObjectId()) {
		case GarageScript::c_LeftArrow_Ctl:
		case GarageScript::c_RightArrow_Ctl:
			m_state->m_unk0x14.m_unk0x00 = 0;
			m_destLocation = LegoGameState::Area::e_garadoor;

			m_state->FUN_10006490();
			m_radio.Stop();
			BackgroundAudioManager()->Stop();
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case GarageScript::c_Info_Ctl:
			m_state->m_unk0x14.m_unk0x00 = 0;
			m_destLocation = LegoGameState::Area::e_infomain;

			m_state->FUN_10006490();
			m_radio.Stop();
			BackgroundAudioManager()->Stop();
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case GarageScript::c_Buggy_Ctl:
			m_state->m_unk0x14.m_unk0x00 = 0;
			m_destLocation = LegoGameState::Area::e_dunecarbuild;

			m_state->FUN_10006490();
			m_radio.Stop();
			BackgroundAudioManager()->Stop();
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		}
	}

	return 1;
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

// FUNCTION: LEGO1 0x10005c90
MxResult GasStation::Tickle()
{
	if (!m_worldStarted) {
		LegoWorld::Tickle();
		return SUCCESS;
	}

	if (g_unk0x100f0160 != 0) {
		g_unk0x100f0160--;
	}

	MxLong time = Timer()->GetTime();

	if (m_unk0x114) {
		if (time - m_unk0x10c > 15000) {
			m_unk0x10c = time;
			if (m_unk0x104 == 1) {
				m_unk0x104 = 2;
			}
			else if (m_unk0x104 != 0) {
				m_unk0x104 = 0;
				MxDSAction action;
				m_state->m_unk0x14.m_unk0x00 = 9;
				PlayAction(GarageScript::c_wgs031nu_RunAnim);
				m_unk0x106 = 1;
			}
		}
	}

	if (m_unk0x115) {
		if (time - m_trackLedTimer > 300) {
			m_trackLedTimer = time;
			g_trackLedEnabled = !g_trackLedEnabled;
			m_trackLedBitmap->Enable(g_trackLedEnabled);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10005e70
MxBool GasStation::VTable0x64()
{
	m_radio.Stop();
	m_state->FUN_10006490();
	m_state->m_unk0x14.m_unk0x00 = 0;
	m_destLocation = LegoGameState::Area::e_infomain;
	return TRUE;
}
