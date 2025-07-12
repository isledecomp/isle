#include "gasstation.h"

#include "garage_actions.h"
#include "isle.h"
#include "islepathactor.h"
#include "jukebox.h"
#include "jukebox_actions.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legomain.h"
#include "legoutils.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstillpresenter.h"
#include "mxticklemanager.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "radio.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(GasStation, 0x128)
DECOMP_SIZE_ASSERT(GasStationState, 0x24)

// GLOBAL: LEGO1 0x100f0160
MxS32 g_animationSkipCounterGasStation = 3;

// GLOBAL: LEGO1 0x100f0164
MxBool g_trackLedEnabled = FALSE;

// FUNCTION: LEGO1 0x100046a0
GasStation::GasStation()
{
	m_currentActorId = LegoActor::c_none;
	m_state = NULL;
	m_destLocation = LegoGameState::e_undefined;
	m_trackLedBitmap = NULL;
	m_waitingState = e_finished;
	m_waiting = FALSE;
	m_setWithCurrentAction = 0;
	m_lastIdleAnimation = 0;
	m_flashingLeds = FALSE;
	m_trackLedTimer = 0;

	NotificationManager()->Register(this);
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
	g_animationSkipCounterGasStation = 3;
}

// FUNCTION: LEGO1 0x10004990
// FUNCTION: BETA10 0x100286c0
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
		m_state->m_state = GasStationState::e_newState;
	}
	else if (m_state->m_state == GasStationState::e_unknown4) {
		m_state->m_state = GasStationState::e_unknown4;
	}
	else {
		m_state->m_state = GasStationState::e_unknown3;
	}

	GameState()->m_currentArea = LegoGameState::e_garage;
	GameState()->StopArea(LegoGameState::e_previousArea);

	InputManager()->Register(this);
	SetIsWorldActive(FALSE);
	return result;
}

// FUNCTION: LEGO1 0x10004a60
// FUNCTION: BETA10 0x10028883
MxLong GasStation::Notify(MxParam& p_param)
{
	MxNotificationParam& param = (MxNotificationParam&) p_param;
	MxResult result = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (param.GetNotification()) {
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationKeyPress:
			result = HandleKeyPress((((LegoEventNotificationParam&) p_param)).GetKey());
			break;
		case c_notificationButtonDown:
			result = HandleButtonDown(((LegoControlManagerNotificationParam&) p_param));
			break;
		case c_notificationControl:
			result = HandleControl((LegoControlManagerNotificationParam&) p_param);
			break;
		case c_notificationTransitioned:
			assert(m_destLocation != LegoGameState::e_undefined);
			GameState()->SwitchArea(m_destLocation);
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10004b30
// FUNCTION: BETA10 0x10028a5e
void GasStation::ReadyWorld()
{
	PlayMusic(JukeboxScript::c_JBMusic2);

	m_trackLedBitmap = (MxStillPresenter*) Find("MxStillPresenter", "TrackLed_Bitmap");
	m_currentActorId = UserActor()->GetActorId();

	switch (m_currentActorId) {
	case LegoActor::c_pepper:
		switch (m_state->m_pepperAction) {
		case 0:
			m_state->m_state = GasStationState::e_introduction;
			PlayAction(GarageScript::c_wgs002nu_RunAnim);
			m_setWithCurrentAction = 1;
			break;
		case 1:
			m_state->m_state = GasStationState::e_introduction;
			PlayAction(GarageScript::c_wgs003nu_RunAnim);
			m_setWithCurrentAction = 1;
			break;
		case 2:
			m_state->m_state = GasStationState::e_introduction;
			PlayAction(GarageScript::c_wgs004nu_RunAnim);
			m_setWithCurrentAction = 1;
			break;
		default:
			m_state->m_state = GasStationState::e_explainQuest;
			PlayAction(GarageScript::c_wgs008nu_RunAnim);
			m_setWithCurrentAction = 1;
			m_waitingState = e_start;
			break;
		}

		if (m_state->m_pepperAction < 5) {
			m_state->m_pepperAction++;
		}
		break;
	case LegoActor::c_mama:
		switch (m_state->m_mamaAction) {
		case 0:
			m_state->m_state = GasStationState::e_introduction;
			PlayAction(GarageScript::c_wgs006nu_RunAnim);
			m_setWithCurrentAction = 1;
			break;
		case 1:
			m_state->m_state = GasStationState::e_introduction;
			PlayAction(GarageScript::c_wgs007nu_RunAnim);
			m_setWithCurrentAction = 1;
			break;
		default:
			m_state->m_state = GasStationState::e_explainQuest;
			PlayAction(GarageScript::c_wgs008nu_RunAnim);
			m_setWithCurrentAction = 1;
			m_waitingState = e_start;
			break;
		}

		if (m_state->m_mamaAction < 5) {
			m_state->m_mamaAction++;
		}
		break;
	case LegoActor::c_nick:
		switch (m_state->m_nickAction) {
		case 0:
			m_state->m_state = GasStationState::e_introduction;
			PlayAction(GarageScript::c_wgs009nu_RunAnim);
			m_setWithCurrentAction = 1;
			break;
		case 1:
			m_state->m_state = GasStationState::e_introduction;
			PlayAction(GarageScript::c_wgs010nu_RunAnim);
			m_setWithCurrentAction = 1;
			break;
		default:
			m_state->m_state = GasStationState::e_explainQuest;
			PlayAction(GarageScript::c_wgs008nu_RunAnim);
			m_setWithCurrentAction = 1;
			m_waitingState = e_start;
			break;
		}

		if (m_state->m_nickAction < 5) {
			m_state->m_nickAction++;
		}
		break;
	case LegoActor::c_papa:
		switch (m_state->m_papaAction) {
		case 0:
			m_state->m_state = GasStationState::e_introduction;
			PlayAction(GarageScript::c_wgs012nu_RunAnim);
			m_setWithCurrentAction = 1;
			break;
		case 1:
			m_state->m_state = GasStationState::e_introduction;
			PlayAction(GarageScript::c_wgs014nu_RunAnim);
			m_setWithCurrentAction = 1;
			break;
		default:
			m_state->m_state = GasStationState::e_explainQuest;
			PlayAction(GarageScript::c_wgs017nu_RunAnim);
			m_setWithCurrentAction = 1;
			m_waitingState = e_start;
			break;
		}

		if (m_state->m_papaAction < 5) {
			m_state->m_papaAction++;
		}
		break;
	case LegoActor::c_laura:
		switch (m_state->m_lauraAction) {
		case 0:
			m_state->m_state = GasStationState::e_introduction;
			PlayAction(GarageScript::c_wgs020nu_RunAnim);
			m_setWithCurrentAction = 1;
			break;
		case 1:
			m_state->m_state = GasStationState::e_introduction;
			PlayAction(GarageScript::c_wgs021nu_RunAnim);
			m_setWithCurrentAction = 1;
			break;
		default:
			m_state->m_state = GasStationState::e_explainQuest;
			PlayAction(GarageScript::c_wgs022nu_RunAnim);
			m_setWithCurrentAction = 1;
			m_waitingState = e_start;
			break;
		}

		if (m_state->m_lauraAction < 5) {
			m_state->m_lauraAction++;
		}
		break;
	default:
		break;
	}

	Disable(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x10005590
// FUNCTION: BETA10 0x10029e30
inline void GasStation::PlayAction(GarageScript::Script p_objectId)
{
	MxDSAction action;
	action.SetAtomId(*g_garageScript);
	action.SetObjectId(p_objectId);

	BackgroundAudioManager()->LowerVolume();
	Start(&action);
	m_state->PlayAction(p_objectId);
}

// FUNCTION: BETA10 0x10029f00
inline void GasStation::StopAction(GarageScript::Script p_objectId)
{
	if (p_objectId != GarageScript::c_noneGarage) {
		InvokeAction(Extra::e_stop, *g_garageScript, p_objectId, NULL);
		BackgroundAudioManager()->RaiseVolume();
		m_state->StopAction(p_objectId);
	}
}

// FUNCTION: LEGO1 0x10005660
MxLong GasStation::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	MxLong result = m_radio.Notify(p_param);

	if (result == 0) {
		MxDSAction* action = p_param.GetAction();

		if (action->GetAtomId() == m_atomId && action->GetObjectId()) {
			m_state->StopAction((GarageScript::Script) action->GetObjectId());
			m_setWithCurrentAction = 0;

			switch (m_state->m_state) {
			case GasStationState::e_introduction:
				g_animationSkipCounterGasStation = 0;
				m_state->m_state = GasStationState::e_explainQuest;
				m_flashingLeds = TRUE;
				PlayAction(GarageScript::c_wgs023nu_RunAnim);
				m_setWithCurrentAction = 1;
				m_waitingState = e_start;
				break;
			case GasStationState::e_explainQuest:
				g_animationSkipCounterGasStation = 0;
				m_flashingLeds = TRUE;

				if (m_waitingState == e_canceled) {
					m_state->m_state = GasStationState::e_afterAcceptingQuest;
					PlayAction(GarageScript::c_wgs029nu_RunAnim);
					m_setWithCurrentAction = 1;
				}
				else {
					m_state->m_state = GasStationState::e_waitAcceptingQuest;
					m_waiting = TRUE;
				}
				break;
			case GasStationState::e_afterAcceptingQuest:
				m_state->m_state = GasStationState::e_beforeExitingForQuest;
				((Act1State*) GameState()->GetState("Act1State"))->m_unk0x018 = 7;
				m_destLocation = LegoGameState::e_garageExited;
				m_radio.Stop();
				BackgroundAudioManager()->Stop();
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
				break;
			}

			result = 1;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10005920
MxLong GasStation::HandleKeyPress(MxS8 p_key)
{
	if (p_key == VK_SPACE && g_animationSkipCounterGasStation == 0 && m_setWithCurrentAction != 0) {
		m_state->StopActions();
		return 1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x10005960
// FUNCTION: BETA10 0x10029319
MxLong GasStation::HandleButtonDown(LegoControlManagerNotificationParam& p_param)
{
	if (m_waitingState == e_start || m_waitingState == e_started) {
		LegoROI* roi = PickROI(p_param.GetX(), p_param.GetY());

		if (roi != NULL) {
			if (!strnicmp(roi->GetName(), "capdb", 5) || !strnicmp(roi->GetName(), "*capdb", 6)) {
				m_waitingState = e_canceled;
				m_waiting = FALSE;

				if (m_state->m_state == GasStationState::e_waitAcceptingQuest) {
					m_state->m_state = GasStationState::e_afterAcceptingQuest;
					PlayAction(GarageScript::c_wgs029nu_RunAnim);
					m_setWithCurrentAction = 1;
				}
				else {
					StopAction(GarageScript::c_wgs023nu_RunAnim);
				}

				return 1;
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10005b20
// FUNCTION: BETA10 0x10029445
MxLong GasStation::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	if (p_param.m_unk0x28 == 1) {
		MxDSAction action;

		switch (p_param.m_clickedObjectId) {
		case GarageScript::c_LeftArrow_Ctl:
		case GarageScript::c_RightArrow_Ctl:
			m_state->m_state = GasStationState::e_unknown0;
			m_destLocation = LegoGameState::Area::e_garadoor;

			m_state->StopActions();
			m_radio.Stop();
			BackgroundAudioManager()->Stop();
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case GarageScript::c_Info_Ctl:
			m_state->m_state = GasStationState::e_unknown0;
			m_destLocation = LegoGameState::Area::e_infomain;

			m_state->StopActions();
			m_radio.Stop();
			BackgroundAudioManager()->Stop();
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case GarageScript::c_Buggy_Ctl:
			m_state->m_state = GasStationState::e_unknown0;
			m_destLocation = LegoGameState::Area::e_dunecarbuild;

			m_state->StopActions();
			m_radio.Stop();
			BackgroundAudioManager()->Stop();
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x10005c40
// FUNCTION: BETA10 0x10029551
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
// FUNCTION: BETA10 0x100295c6
MxResult GasStation::Tickle()
{
	if (!m_worldStarted) {
		LegoWorld::Tickle();
		return SUCCESS;
	}

	if (g_animationSkipCounterGasStation != 0) {
		g_animationSkipCounterGasStation--;
	}

	MxLong time = Timer()->GetTime();

	if (m_waiting) {
		if (time - m_lastIdleAnimation > 15000) {
			m_lastIdleAnimation = time;
			if (m_waitingState == e_start) {
				m_waitingState = e_started;
			}
			else if (m_waitingState != e_finished) {
				m_waitingState = e_finished;
				MxDSAction action;
				m_state->m_state = GasStationState::e_cancelQuest;
				PlayAction(GarageScript::c_wgs031nu_RunAnim);
				m_setWithCurrentAction = 1;
			}
		}
	}

	if (m_flashingLeds) {
		if (time - m_trackLedTimer > 300) {
			m_trackLedTimer = time;
			g_trackLedEnabled = !g_trackLedEnabled;
			m_trackLedBitmap->Enable(g_trackLedEnabled);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10005e70
MxBool GasStation::Escape()
{
	m_radio.Stop();
	m_state->StopActions();
	m_state->m_state = GasStationState::e_unknown0;
	m_destLocation = LegoGameState::Area::e_infomain;
	return TRUE;
}

// FUNCTION: LEGO1 0x10005eb0
// FUNCTION: BETA10 0x100296b8
GasStationState::GasStationState()
{
	m_pepperAction = 0;
	m_mamaAction = 0;
	m_papaAction = 0;
	m_nickAction = 0;
	m_lauraAction = 0;
	memset(m_actions, GarageScript::c_noneGarage, sizeof(m_actions));
}

// FUNCTION: LEGO1 0x10006300
// FUNCTION: BETA10 0x10029754
MxResult GasStationState::Serialize(LegoStorage* p_storage)
{
	LegoState::Serialize(p_storage);

	if (p_storage->IsWriteMode()) {
		p_storage->WriteS16(m_pepperAction);
		p_storage->WriteS16(m_mamaAction);
		p_storage->WriteS16(m_papaAction);
		p_storage->WriteS16(m_nickAction);
		p_storage->WriteS16(m_lauraAction);
	}
	else if (p_storage->IsReadMode()) {
		p_storage->ReadS16(m_pepperAction);
		p_storage->ReadS16(m_mamaAction);
		p_storage->ReadS16(m_papaAction);
		p_storage->ReadS16(m_nickAction);
		p_storage->ReadS16(m_lauraAction);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10006430
void GasStationState::PlayAction(GarageScript::Script p_objectId)
{
	for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_actions); i++) {
		if (m_actions[i] == GarageScript::c_noneGarage) {
			m_actions[i] = p_objectId;
			return;
		}
	}
}

// FUNCTION: LEGO1 0x10006460
void GasStationState::StopAction(GarageScript::Script p_objectId)
{
	for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_actions); i++) {
		if (m_actions[i] == p_objectId) {
			m_actions[i] = GarageScript::c_noneGarage;
			return;
		}
	}
}

// FUNCTION: LEGO1 0x10006490
void GasStationState::StopActions()
{
	for (MxS32 i = 0; i < (MxS32) sizeOfArray(m_actions); i++) {
		if (m_actions[i] != GarageScript::c_noneGarage) {
			InvokeAction(Extra::e_stop, *g_garageScript, m_actions[i], NULL);
			m_actions[i] = GarageScript::c_noneGarage;
		}
	}

	BackgroundAudioManager()->RaiseVolume();
}
