#include "hospital.h"

#include "hospital_actions.h"
#include "isle.h"
#include "islepathactor.h"
#include "jukebox.h"
#include "jukebox_actions.h"
#include "legocontrolmanager.h"
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
#include "scripts.h"

DECOMP_SIZE_ASSERT(Hospital, 0x12c)
DECOMP_SIZE_ASSERT(HospitalState, 0x18)

// GLOBAL: LEGO1 0x100f7918
undefined4 g_animationSkipCounterHospital = 3;

// GLOBAL: LEGO1 0x100f791c
MxBool g_copLedEnabled = FALSE;

// GLOBAL: LEGO1 0x100f7920
MxBool g_pizzaLedEnabled = FALSE;

// FUNCTION: LEGO1 0x100745e0
Hospital::Hospital()
{
	m_currentActorId = LegoActor::c_none;
	m_interactionMode = 0;
	m_hospitalState = NULL;
	m_setWithCurrentAction = 0;
	m_destLocation = LegoGameState::e_undefined;
	m_currentAction = HospitalScript::c__StartUp;
	m_copLedBitmap = NULL;
	m_pizzaLedBitmap = NULL;
	m_flashingLeds = 0;
	m_copLedAnimTimer = 0;
	m_pizzaLedAnimTimer = 0;
	m_unk0x128 = 0;
	NotificationManager()->Register(this);
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

	m_hospitalState->m_state = HospitalState::e_unknown3;

	NotificationManager()->Unregister(this);
	g_animationSkipCounterHospital = 3;
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
		m_hospitalState->m_state = HospitalState::e_newState;
	}
	else if (m_hospitalState->m_state == HospitalState::e_unknown4) {
		m_hospitalState->m_state = HospitalState::e_unknown4;
	}
	else {
		m_hospitalState->m_state = HospitalState::e_unknown3;
	}

	GameState()->m_currentArea = LegoGameState::e_hospital;
	GameState()->StopArea(LegoGameState::e_previousArea);

	InputManager()->Register(this);
	EnableAnimations(FALSE);

	return result;
}

// FUNCTION: LEGO1 0x10074990
// FUNCTION: BETA10 0x1002ca3b
MxLong Hospital::Notify(MxParam& p_param)
{
	MxLong result = 0;
	MxNotificationParam& param = (MxNotificationParam&) p_param;
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

	if (UserActor() == NULL) {
		m_currentActorId = LegoActor::c_laura;
	}
	else {
		m_currentActorId = UserActor()->GetActorId();
	}

	switch (m_currentActorId) {
	case LegoActor::c_pepper:
		m_hospitalState->m_stateActor = m_hospitalState->m_statePepper;

		if (m_hospitalState->m_statePepper < 5) {
			m_hospitalState->m_statePepper += 1;
		}

		break;
	case LegoActor::c_mama:
		m_hospitalState->m_stateActor = m_hospitalState->m_stateMama;

		if (m_hospitalState->m_stateMama < 5) {
			m_hospitalState->m_stateMama += 1;
		}

		break;
	case LegoActor::c_papa:
		m_hospitalState->m_stateActor = m_hospitalState->m_statePapa;

		if (m_hospitalState->m_statePapa < 5) {
			m_hospitalState->m_statePapa += 1;
		}

		break;
	case LegoActor::c_nick:
		m_hospitalState->m_stateActor = m_hospitalState->m_stateNick;

		if (m_hospitalState->m_stateNick < 5) {
			m_hospitalState->m_stateNick += 1;
		}

		break;
	case LegoActor::c_laura:
		m_hospitalState->m_stateActor = m_hospitalState->m_stateLaura;

		if (m_hospitalState->m_stateLaura < 5) {
			m_hospitalState->m_stateLaura += 1;
		}

		break;
	}

	if (m_hospitalState->m_stateActor < 3) {
		HospitalScript::Script hospitalScript[] = {
			HospitalScript::c_hho002cl_RunAnim,
			HospitalScript::c_hho004jk_RunAnim,
			HospitalScript::c_hho007p1_RunAnim
		};

		m_hospitalState->m_state = HospitalState::e_introduction;

		PlayAction(hospitalScript[m_hospitalState->m_stateActor]);
		m_currentAction = hospitalScript[m_hospitalState->m_stateActor];
		m_setWithCurrentAction = 1;
	}
	else {
		m_interactionMode = 1;
		m_time = Timer()->GetTime();

		m_hospitalState->m_state = HospitalState::e_explainQuestShort;

		PlayAction(HospitalScript::c_hho003cl_RunAnim);
		m_currentAction = HospitalScript::c_hho003cl_RunAnim;
		m_setWithCurrentAction = 1;
	}

	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x10074dd0
MxLong Hospital::HandleKeyPress(MxS8 p_key)
{
	MxLong result = 0;

	if (p_key == VK_SPACE && g_animationSkipCounterHospital == 0) {
		DeleteObjects(&m_atomId, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
		result = 1;
	}

	return result;
}

// FUNCTION: LEGO1 0x10074e00
MxLong Hospital::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	MxLong result = 0;
	MxDSAction* action = p_param.GetAction();
	Act1State* act1State;

	if (action->GetAtomId() != m_atomId) {
		return result;
	}

	m_setWithCurrentAction = 0;

	switch (m_hospitalState->m_state) {
	case HospitalState::e_introduction:
		m_hospitalState->m_state = HospitalState::e_explainQuest;
		PlayAction(HospitalScript::c_hho006cl_RunAnim);

		m_currentAction = HospitalScript::c_hho006cl_RunAnim;
		m_setWithCurrentAction = 1;
		m_flashingLeds = 1;
		g_animationSkipCounterHospital = 0;
		break;
	case HospitalState::e_explainQuestShort:
		m_time = Timer()->GetTime();
		m_interactionMode = 1;
		break;
	case HospitalState::e_explainQuest:
	case HospitalState::e_unknown10:
		m_hospitalState->m_state = HospitalState::e_waitAcceptingQuest;
		m_interactionMode = 1;
		m_time = Timer()->GetTime();
		break;
	case HospitalState::e_unknown11:
		switch (m_currentActorId) {
		case LegoActor::c_pepper:
			switch (m_hospitalState->m_statePepper) {
			case 0:
			case 1:
				m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
				PlayAction(HospitalScript::c_hho017cl_RunAnim);

				m_currentAction = HospitalScript::c_hho017cl_RunAnim;
				m_setWithCurrentAction = 1;
				break;
			default:
				m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
				PlayAction(HospitalScript::c_hho018cl_RunAnim);

				m_currentAction = HospitalScript::c_hho018cl_RunAnim;
				m_setWithCurrentAction = 1;
				break;
			}
			break;
		case LegoActor::c_mama:
			switch (m_hospitalState->m_stateMama) {
			case 0:
			case 1:
				m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
				PlayAction(HospitalScript::c_hho019cl_RunAnim);

				m_currentAction = HospitalScript::c_hho019cl_RunAnim;
				m_setWithCurrentAction = 1;
				break;
			default:
				m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
				PlayAction(HospitalScript::c_hho020cl_RunAnim);

				m_currentAction = HospitalScript::c_hho020cl_RunAnim;
				m_setWithCurrentAction = 1;
				break;
			}
			break;
		case LegoActor::c_papa:
			switch (m_hospitalState->m_statePapa) {
			case 0:
			case 1:
				m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
				PlayAction(HospitalScript::c_hho023cl_RunAnim);

				m_currentAction = HospitalScript::c_hho023cl_RunAnim;
				m_setWithCurrentAction = 1;
				break;
			default:
				m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
				PlayAction(HospitalScript::c_hho024cl_RunAnim);

				m_currentAction = HospitalScript::c_hho024cl_RunAnim;
				m_setWithCurrentAction = 1;
				break;
			}
			break;
		case LegoActor::c_nick:
			switch (m_hospitalState->m_stateNick) {
			case 0:
			case 1:
				m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
				PlayAction(HospitalScript::c_hho021cl_RunAnim);

				m_currentAction = HospitalScript::c_hho021cl_RunAnim;
				m_setWithCurrentAction = 1;
				break;
			default:
				m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
				PlayAction(HospitalScript::c_hhoa22cl_RunAnim);

				m_currentAction = HospitalScript::c_hhoa22cl_RunAnim;
				m_setWithCurrentAction = 1;
				break;
			}
			break;
		case LegoActor::c_laura:
			switch (m_hospitalState->m_stateLaura) {
			case 0:
			case 1:
				m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
				PlayAction(HospitalScript::c_hho025cl_RunAnim);

				m_currentAction = HospitalScript::c_hho025cl_RunAnim;
				m_setWithCurrentAction = 1;
				break;
			default:
				m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
				PlayAction(HospitalScript::c_hho026cl_RunAnim);

				m_currentAction = HospitalScript::c_hho026cl_RunAnim;
				m_setWithCurrentAction = 1;
				break;
			}
			break;
		}
		break;
	case HospitalState::e_afterAcceptingQuest:
		m_hospitalState->m_state = HospitalState::e_beforeEnteringAmbulance;
		act1State = (Act1State*) GameState()->GetState("Act1State");
		act1State->SetUnknown18(9);
	case HospitalState::e_exitToFront:
		if (m_unk0x128 == 0) {
			m_unk0x128 = 1;
			m_destLocation = LegoGameState::e_hospitalExited;

			DeleteObjects(&m_atomId, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		}
		break;
	case HospitalState::e_exitToInfocenter:
		if (m_unk0x128 == 0) {
			m_unk0x128 = 1;
			m_destLocation = LegoGameState::e_infomain;

			DeleteObjects(&m_atomId, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		}
		break;
	}

	result = 1;

	return result;
}

// FUNCTION: LEGO1 0x10075710
// FUNCTION: BETA10 0x1002d2b1
MxLong Hospital::HandleButtonDown(LegoControlManagerNotificationParam& p_param)
{
	if (m_interactionMode == 1) {
		LegoROI* roi = PickROI(p_param.GetX(), p_param.GetY());
		if (roi != NULL) {
			const LegoChar* roiName = roi->GetName();

			if (roiName[0] == '*') {
				roiName += 1;
			}

			if (!strcmpi("actor_ha", roiName)) {
				InputManager()->DisableInputProcessing();

				m_interactionMode = 3;

				if (m_hospitalState->m_state == HospitalState::e_explainQuestShort) {
					if (m_unk0x128 == 0) {
						m_unk0x128 = 1;

						TickleManager()->UnregisterClient(this);

						m_hospitalState->m_state = HospitalState::e_beforeEnteringAmbulance;
						Act1State* act1State = (Act1State*) GameState()->GetState("Act1State");
						assert(act1State);

						act1State->m_unk0x018 = 9;

						m_destLocation = LegoGameState::e_hospitalExited;
						DeleteObjects(
							&m_atomId,
							HospitalScript::c_hho002cl_RunAnim,
							HospitalScript::c_hho006cl_RunAnim
						);
						TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
					}
				}
				else if (m_hospitalState->m_state == HospitalState::e_unknown10 || m_hospitalState->m_state == HospitalState::e_waitAcceptingQuest) {
					if (m_hospitalState->m_state == HospitalState::e_unknown10) {
						m_hospitalState->m_state = HospitalState::e_unknown11;

						BackgroundAudioManager()->RaiseVolume();
						DeleteObjects(
							&m_atomId,
							HospitalScript::c_hho002cl_RunAnim,
							HospitalScript::c_hho006cl_RunAnim
						);
					}
					else {
						switch (m_currentActorId) {
						case LegoActor::c_pepper:
							switch (m_hospitalState->m_statePepper) {
							case 0:
							case 1:
								m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
								PlayAction(HospitalScript::c_hho017cl_RunAnim);

								m_currentAction = HospitalScript::c_hho017cl_RunAnim;
								m_setWithCurrentAction = 1;
								break;
							default:
								m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
								PlayAction(HospitalScript::c_hho018cl_RunAnim);

								m_currentAction = HospitalScript::c_hho018cl_RunAnim;
								m_setWithCurrentAction = 1;
								break;
							}
							break;
						case LegoActor::c_mama:
							switch (m_hospitalState->m_stateMama) {
							case 0:
							case 1:
								m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
								PlayAction(HospitalScript::c_hho019cl_RunAnim);

								m_currentAction = HospitalScript::c_hho019cl_RunAnim;
								m_setWithCurrentAction = 1;
								break;
							default:
								m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
								PlayAction(HospitalScript::c_hho020cl_RunAnim);

								m_currentAction = HospitalScript::c_hho020cl_RunAnim;
								m_setWithCurrentAction = 1;
								break;
							}
							break;
						case LegoActor::c_nick:
							switch (m_hospitalState->m_stateNick) {
							case 0:
							case 1:
								m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
								PlayAction(HospitalScript::c_hho021cl_RunAnim);

								m_currentAction = HospitalScript::c_hho021cl_RunAnim;
								m_setWithCurrentAction = 1;
								break;
							default:
								m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
								PlayAction(HospitalScript::c_hhoa22cl_RunAnim);

								m_currentAction = HospitalScript::c_hhoa22cl_RunAnim;
								m_setWithCurrentAction = 1;
								break;
							}
							break;
						case LegoActor::c_papa:
							switch (m_hospitalState->m_statePapa) {
							case 0:
							case 1:
								m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
								PlayAction(HospitalScript::c_hho023cl_RunAnim);

								m_currentAction = HospitalScript::c_hho023cl_RunAnim;
								m_setWithCurrentAction = 1;
								break;
							default:
								m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
								PlayAction(HospitalScript::c_hho024cl_RunAnim);

								m_currentAction = HospitalScript::c_hho024cl_RunAnim;
								m_setWithCurrentAction = 1;
								break;
							}
							break;
						case LegoActor::c_laura:
							switch (m_hospitalState->m_stateLaura) {
							case 0:
							case 1:
								m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
								PlayAction(HospitalScript::c_hho025cl_RunAnim);

								m_currentAction = HospitalScript::c_hho025cl_RunAnim;
								m_setWithCurrentAction = 1;
								break;
							default:
								m_hospitalState->m_state = HospitalState::e_afterAcceptingQuest;
								PlayAction(HospitalScript::c_hho026cl_RunAnim);

								m_currentAction = HospitalScript::c_hho026cl_RunAnim;
								m_setWithCurrentAction = 1;
								break;
							}
							break;
						}
					}
				}

				return 1;
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10075f90
MxBool Hospital::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	if (p_param.m_unk0x28 == 1) {
		switch (p_param.m_clickedObjectId) {
		case HospitalScript::c_Info_Ctl:
			BackgroundAudioManager()->RaiseVolume();
			DeleteObjects(&m_atomId, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);

			if (m_interactionMode == 1) {
				m_hospitalState->m_state = HospitalState::e_exitToInfocenter;

				PlayAction(HospitalScript::c_hho016cl_RunAnim);
				m_currentAction = HospitalScript::c_hho016cl_RunAnim;
				m_setWithCurrentAction = 1;
			}
			else if (m_unk0x128 == 0) {
				m_unk0x128 = 1;
				m_hospitalState->m_state = HospitalState::e_exitImmediately;
				m_destLocation = LegoGameState::e_infomain;

				DeleteObjects(&m_atomId, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			}

			break;

		case HospitalScript::c_Door_Ctl:
			DeleteObjects(&m_atomId, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);

			if (m_interactionMode == 1) {
				m_hospitalState->m_state = HospitalState::e_exitToFront;

				PlayAction(HospitalScript::c_hho016cl_RunAnim);
				m_currentAction = HospitalScript::c_hho016cl_RunAnim;
				m_setWithCurrentAction = 1;
			}
			else if (m_unk0x128 == 0) {
				m_unk0x128 = 1;
				m_hospitalState->m_state = HospitalState::e_exitImmediately;
				m_destLocation = LegoGameState::e_hospitalExited;

				DeleteObjects(&m_atomId, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			}

			break;
		}
	}

	return TRUE;
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

	if (g_animationSkipCounterHospital != 0) {
		g_animationSkipCounterHospital -= 1;
	}

	MxLong time = Timer()->GetTime();

	if (m_flashingLeds != 0) {
		if (time - m_copLedAnimTimer > 300) {
			m_copLedAnimTimer = time;
			g_copLedEnabled = !g_copLedEnabled;
			m_copLedBitmap->Enable(g_copLedEnabled);
		}

		if (time - m_pizzaLedAnimTimer > 200) {
			m_pizzaLedAnimTimer = time;
			g_pizzaLedEnabled = !g_pizzaLedEnabled;
			m_pizzaLedBitmap->Enable(g_pizzaLedEnabled);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10076330
MxBool Hospital::Escape()
{
	DeleteObjects(&m_atomId, HospitalScript::c_hho002cl_RunAnim, 999);
	m_hospitalState->m_state = HospitalState::e_exitToClose;

	m_destLocation = LegoGameState::e_infomain;

	return TRUE;
}

// FUNCTION: LEGO1 0x10076370
HospitalState::HospitalState()
{
	m_stateActor = 0;
	m_statePepper = 0;
	m_stateMama = 0;
	m_statePapa = 0;
	m_stateNick = 0;
	m_stateLaura = 0;
}

// FUNCTION: LEGO1 0x10076530
// FUNCTION: BETA10 0x1002db26
MxResult HospitalState::Serialize(LegoStorage* p_storage)
{
	LegoState::Serialize(p_storage);

	if (p_storage->IsWriteMode()) {
		p_storage->WriteS16(m_stateActor);
		p_storage->WriteS16(m_statePepper);
		p_storage->WriteS16(m_stateMama);
		p_storage->WriteS16(m_statePapa);
		p_storage->WriteS16(m_stateNick);
		p_storage->WriteS16(m_stateLaura);
	}
	else if (p_storage->IsReadMode()) {
		p_storage->ReadS16(m_stateActor);
		p_storage->ReadS16(m_statePepper);
		p_storage->ReadS16(m_stateMama);
		p_storage->ReadS16(m_statePapa);
		p_storage->ReadS16(m_stateNick);
		p_storage->ReadS16(m_stateLaura);
	}

	return SUCCESS;
}
