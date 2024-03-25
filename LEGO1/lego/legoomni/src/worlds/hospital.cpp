#include "hospital.h"

#include "act1state.h"
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
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(Hospital, 0x12c)

// GLOBAL: LEGO1 0x100f7918
undefined4 g_unk0x100f7918 = 3;

// GLOBAL: LEGO1 0x100f791c
MxBool g_copLedEnabled = FALSE;

// GLOBAL: LEGO1 0x100f7920
MxBool g_pizzaLedEnabled = FALSE;

// FUNCTION: LEGO1 0x100745e0
Hospital::Hospital()
{
	m_currentActorId = 0;
	m_unk0x100 = 0;
	m_hospitalState = NULL;
	m_unk0x108 = 0;
	m_destLocation = LegoGameState::e_undefined;
	m_currentAction = HospitalScript::c__StartUp;
	m_copLedBitmap = NULL;
	m_pizzaLedBitmap = NULL;
	m_unk0x118 = 0;
	m_copLedAnimTimer = 0;
	m_pizzaLedAnimTimer = 0;
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
		m_currentAction = hospitalScript[m_hospitalState->m_unk0x0c];
	}
	else {
		m_unk0x100 = 1;
		m_time = Timer()->GetTime();

		m_hospitalState->m_unk0x08.m_unk0x00 = 6;

		PlayAction(HospitalScript::c_hho003cl_RunAnim);
		m_currentAction = HospitalScript::c_hho003cl_RunAnim;
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

// FUNCTION: LEGO1 0x10074e00
MxLong Hospital::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	MxLong result = 0;
	MxDSAction* action = p_param.GetAction();
	Act1State* act1State;

	if (action->GetAtomId() != m_atom) {
		return result;
	}

	m_unk0x108 = 0;

	switch (m_hospitalState->m_unk0x08.m_unk0x00) {
	case 5:
		m_hospitalState->m_unk0x08.m_unk0x00 = 7;
		PlayAction(HospitalScript::c_hho006cl_RunAnim);

		m_currentAction = HospitalScript::c_hho006cl_RunAnim;
		m_unk0x108 = 1;
		m_unk0x118 = 1;
		g_unk0x100f7918 = 0;
		break;
	case 6:
		m_time = Timer()->GetTime();
		m_unk0x100 = 1;
		break;
	case 7:
	case 10:
		m_hospitalState->m_unk0x08.m_unk0x00 = 8;
		m_unk0x100 = 1;
		m_time = Timer()->GetTime();
		break;
	case 11:
		switch (m_currentActorId) {
		case 1:
			switch (m_hospitalState->m_unk0x0e) {
			case 0:
			case 1:
				m_hospitalState->m_unk0x08.m_unk0x00 = 12;
				PlayAction(HospitalScript::c_hho017cl_RunAnim);

				m_currentAction = HospitalScript::c_hho017cl_RunAnim;
				m_unk0x108 = 1;
				break;
			default:
				m_hospitalState->m_unk0x08.m_unk0x00 = 12;
				PlayAction(HospitalScript::c_hho018cl_RunAnim);

				m_currentAction = HospitalScript::c_hho018cl_RunAnim;
				m_unk0x108 = 1;
				break;
			}
			break;
		case 2:
			switch (m_hospitalState->m_unk0x10) {
			case 0:
			case 1:
				m_hospitalState->m_unk0x08.m_unk0x00 = 12;
				PlayAction(HospitalScript::c_hho019cl_RunAnim);

				m_currentAction = HospitalScript::c_hho019cl_RunAnim;
				m_unk0x108 = 1;
				break;
			default:
				m_hospitalState->m_unk0x08.m_unk0x00 = 12;
				PlayAction(HospitalScript::c_hho020cl_RunAnim);

				m_currentAction = HospitalScript::c_hho020cl_RunAnim;
				m_unk0x108 = 1;
				break;
			}
			break;
		case 3:
			switch (m_hospitalState->m_unk0x12) {
			case 0:
			case 1:
				m_hospitalState->m_unk0x08.m_unk0x00 = 12;
				PlayAction(HospitalScript::c_hho023cl_RunAnim);

				m_currentAction = HospitalScript::c_hho023cl_RunAnim;
				m_unk0x108 = 1;
				break;
			default:
				m_hospitalState->m_unk0x08.m_unk0x00 = 12;
				PlayAction(HospitalScript::c_hho024cl_RunAnim);

				m_currentAction = HospitalScript::c_hho024cl_RunAnim;
				m_unk0x108 = 1;
				break;
			}
			break;
		case 4:
			switch (m_hospitalState->m_unk0x14) {
			case 0:
			case 1:
				m_hospitalState->m_unk0x08.m_unk0x00 = 12;
				PlayAction(HospitalScript::c_hho021cl_RunAnim);

				m_currentAction = HospitalScript::c_hho021cl_RunAnim;
				m_unk0x108 = 1;
				break;
			default:
				m_hospitalState->m_unk0x08.m_unk0x00 = 12;
				PlayAction(HospitalScript::c_hhoa22cl_RunAnim);

				m_currentAction = HospitalScript::c_hhoa22cl_RunAnim;
				m_unk0x108 = 1;
				break;
			}
			break;
		case 5:
			switch (m_hospitalState->m_unk0x16) {
			case 0:
			case 1:
				m_hospitalState->m_unk0x08.m_unk0x00 = 12;
				PlayAction(HospitalScript::c_hho025cl_RunAnim);

				m_currentAction = HospitalScript::c_hho025cl_RunAnim;
				m_unk0x108 = 1;
				break;
			default:
				m_hospitalState->m_unk0x08.m_unk0x00 = 12;
				PlayAction(HospitalScript::c_hho026cl_RunAnim);

				m_currentAction = HospitalScript::c_hho026cl_RunAnim;
				m_unk0x108 = 1;
				break;
			}
			break;
		}
		break;
	case 12:
		m_hospitalState->m_unk0x08.m_unk0x00 = 9;
		act1State = (Act1State*) GameState()->GetState("Act1State");
		act1State->SetUnknown18(9);
	case 14:
		if (m_unk0x128 == 0) {
			m_unk0x128 = 1;
			m_destLocation = LegoGameState::e_unk31;

			DeleteObjects(&m_atom, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		}
		break;
	case 15:
		if (m_unk0x128 == 0) {
			m_unk0x128 = 1;
			m_destLocation = LegoGameState::e_infomain;

			DeleteObjects(&m_atom, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		}
		break;
	}

	result = 1;

	return result;
}

// FUNCTION: LEGO1 0x10075710
MxLong Hospital::HandleButtonDown(LegoControlManagerEvent& p_param)
{
	if (m_unk0x100 == 1) {
		LegoROI* roi = PickROI(p_param.GetX(), p_param.GetY());
		if (roi != NULL) {
			LegoChar* roiName = (LegoChar*) roi->GetName();

			if (roiName[0] == '*') {
				roiName += 1;
			}

			if (!strcmpi("actor_ha", roiName)) {
				LegoInputManager* inputManager = InputManager();
				inputManager->SetUnknown88(TRUE);
				inputManager->SetUnknown336(FALSE);

				m_unk0x100 = 3;

				if (m_hospitalState->m_unk0x08.m_unk0x00 == 6) {
					if (m_unk0x128 == 0) {
						m_unk0x128 = 1;

						TickleManager()->UnregisterClient(this);

						m_hospitalState->m_unk0x08.m_unk0x00 = 9;
						Act1State* act1State = (Act1State*) GameState()->GetState("Act1State");
						act1State->SetUnknown18(9);

						m_destLocation = LegoGameState::e_unk31;
						DeleteObjects(&m_atom, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
						TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
					}
				}
				else if (m_hospitalState->m_unk0x08.m_unk0x00 == 10 || m_hospitalState->m_unk0x08.m_unk0x00 == 8) {
					if (m_hospitalState->m_unk0x08.m_unk0x00 == 10) {
						m_hospitalState->m_unk0x08.m_unk0x00 = 11;

						BackgroundAudioManager()->RaiseVolume();
						DeleteObjects(&m_atom, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
					}
					else {
						switch (m_currentActorId) {
						case 1:
							switch (m_hospitalState->m_unk0x0e) {
							case 0:
							case 1:
								m_hospitalState->m_unk0x08.m_unk0x00 = 12;
								PlayAction(HospitalScript::c_hho017cl_RunAnim);

								m_currentAction = HospitalScript::c_hho017cl_RunAnim;
								m_unk0x108 = 1;
								break;
							default:
								m_hospitalState->m_unk0x08.m_unk0x00 = 12;
								PlayAction(HospitalScript::c_hho018cl_RunAnim);

								m_currentAction = HospitalScript::c_hho018cl_RunAnim;
								m_unk0x108 = 1;
								break;
							}
							break;
						case 2:
							switch (m_hospitalState->m_unk0x10) {
							case 0:
							case 1:
								m_hospitalState->m_unk0x08.m_unk0x00 = 12;
								PlayAction(HospitalScript::c_hho019cl_RunAnim);

								m_currentAction = HospitalScript::c_hho019cl_RunAnim;
								m_unk0x108 = 1;
								break;
							default:
								m_hospitalState->m_unk0x08.m_unk0x00 = 12;
								PlayAction(HospitalScript::c_hho020cl_RunAnim);

								m_currentAction = HospitalScript::c_hho020cl_RunAnim;
								m_unk0x108 = 1;
								break;
							}
							break;
						case 3:
							switch (m_hospitalState->m_unk0x12) {
							case 0:
							case 1:
								m_hospitalState->m_unk0x08.m_unk0x00 = 12;
								PlayAction(HospitalScript::c_hho023cl_RunAnim);

								m_currentAction = HospitalScript::c_hho023cl_RunAnim;
								m_unk0x108 = 1;
								break;
							default:
								m_hospitalState->m_unk0x08.m_unk0x00 = 12;
								PlayAction(HospitalScript::c_hho024cl_RunAnim);

								m_currentAction = HospitalScript::c_hho024cl_RunAnim;
								m_unk0x108 = 1;
								break;
							}
							break;
						case 4:
							switch (m_hospitalState->m_unk0x14) {
							case 0:
							case 1:
								m_hospitalState->m_unk0x08.m_unk0x00 = 12;
								PlayAction(HospitalScript::c_hho021cl_RunAnim);

								m_currentAction = HospitalScript::c_hho021cl_RunAnim;
								m_unk0x108 = 1;
								break;
							default:
								m_hospitalState->m_unk0x08.m_unk0x00 = 12;
								PlayAction(HospitalScript::c_hhoa22cl_RunAnim);

								m_currentAction = HospitalScript::c_hhoa22cl_RunAnim;
								m_unk0x108 = 1;
								break;
							}
							break;
						case 5:
							switch (m_hospitalState->m_unk0x16) {
							case 0:
							case 1:
								m_hospitalState->m_unk0x08.m_unk0x00 = 12;
								PlayAction(HospitalScript::c_hho025cl_RunAnim);

								m_currentAction = HospitalScript::c_hho025cl_RunAnim;
								m_unk0x108 = 1;
								break;
							default:
								m_hospitalState->m_unk0x08.m_unk0x00 = 12;
								PlayAction(HospitalScript::c_hho026cl_RunAnim);

								m_currentAction = HospitalScript::c_hho026cl_RunAnim;
								m_unk0x108 = 1;
								break;
							}
							break;
						}
					}
				}

				return 1;
			}
			else {
				return 0;
			}
		}
	}
	else {
		return 0;
	}

	return 0;
}

// FUNCTION: LEGO1 0x10075f90
MxBool Hospital::HandleClick(LegoControlManagerEvent& p_param)
{
	if (p_param.GetUnknown0x28() == 1) {
		switch (p_param.GetClickedObjectId()) {
		case HospitalScript::c_Info_Ctl:
			BackgroundAudioManager()->RaiseVolume();
			DeleteObjects(&m_atom, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);

			if (m_unk0x100 == 1) {
				m_hospitalState->m_unk0x08.m_unk0x00 = 14;

				PlayAction(HospitalScript::c_hho016cl_RunAnim);
				m_currentAction = HospitalScript::c_hho016cl_RunAnim;
				m_unk0x108 = 1;
			}
			else if (m_unk0x128 == 0) {
				m_unk0x128 = 1;
				m_hospitalState->m_unk0x08.m_unk0x00 = 13;
				m_destLocation = LegoGameState::e_infomain;

				DeleteObjects(&m_atom, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			}

			break;

		case HospitalScript::c_Door_Ctl:
			DeleteObjects(&m_atom, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);

			if (m_unk0x100 == 1) {
				m_hospitalState->m_unk0x08.m_unk0x00 = 15;

				PlayAction(HospitalScript::c_hho016cl_RunAnim);
				m_currentAction = HospitalScript::c_hho016cl_RunAnim;
				m_unk0x108 = 1;
			}
			else if (m_unk0x128 == 0) {
				m_unk0x128 = 1;
				m_hospitalState->m_unk0x08.m_unk0x00 = 13;
				m_destLocation = LegoGameState::e_unk31;

				DeleteObjects(&m_atom, HospitalScript::c_hho002cl_RunAnim, HospitalScript::c_hho006cl_RunAnim);
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

	if (g_unk0x100f7918 != 0) {
		g_unk0x100f7918 -= 1;
	}

	MxLong time = Timer()->GetTime();

	if (m_unk0x118 != 0) {
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
MxBool Hospital::VTable0x64()
{
	DeleteObjects(&m_atom, HospitalScript::c_hho002cl_RunAnim, 999);
	m_hospitalState->m_unk0x08.m_unk0x00 = 0;

	m_destLocation = LegoGameState::e_infomain;

	return TRUE;
}
