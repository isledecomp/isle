#include "isle.h"

#include "3dmanager/lego3dmanager.h"
#include "ambulance.h"
#include "bike.h"
#include "carrace.h"
#include "dunebuggy.h"
#include "helicopter.h"
#include "isle_actions.h"
#include "islepathactor.h"
#include "jetski.h"
#include "jetskirace.h"
#include "jukebox_actions.h"
#include "jukeboxentity.h"
#include "legoanimationmanager.h"
#include "legobackgroundcolor.h"
#include "legocontrolmanager.h"
#include "legoinputmanager.h"
#include "legomain.h"
#include "legonamedtexture.h"
#include "legopathstruct.h"
#include "legoutils.h"
#include "legovariables.h"
#include "legovideomanager.h"
#include "misc.h"
#include "motorcycle.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstillpresenter.h"
#include "mxtransitionmanager.h"
#include "mxvariabletable.h"
#include "pizza.h"
#include "pizzeria.h"
#include "racecar.h"
#include "scripts.h"
#include "skateboard.h"
#include "towtrack.h"
#include "viewmanager/viewmanager.h"

DECOMP_SIZE_ASSERT(Act1State, 0x26c)
DECOMP_SIZE_ASSERT(LegoNamedPlane, 0x4c)
DECOMP_SIZE_ASSERT(Isle, 0x140)

// GLOBAL: LEGO1 0x100f1198
MxU32 g_isleFlags = 0x7f;

// GLOBAL: LEGO1 0x100f37f0
IsleScript::Script g_cptClickDialogue[] =
	{IsleScript::c_Avo905Ps_PlayWav, IsleScript::c_Avo906Ps_PlayWav, IsleScript::c_Avo907Ps_PlayWav};

// FUNCTION: LEGO1 0x10030820
Isle::Isle()
{
	m_pizza = NULL;
	m_pizzeria = NULL;
	m_towtrack = NULL;
	m_ambulance = NULL;
	m_jukebox = NULL;
	m_helicopter = NULL;
	m_bike = NULL;
	m_dunebuggy = NULL;
	m_motocycle = NULL;
	m_skateboard = NULL;
	m_racecar = NULL;
	m_jetski = NULL;
	m_act1state = NULL;
	m_destLocation = LegoGameState::e_undefined;

	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10030a50
Isle::~Isle()
{
	TransitionManager()->SetWaitIndicator(NULL);
	ControlManager()->Unregister(this);

	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	if (UserActor() != NULL) {
		VTable0x6c(UserActor());
	}

	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10030b20
MxResult Isle::Create(MxDSAction& p_dsAction)
{
	GameState()->FindLoadedAct();
	MxResult result = LegoWorld::Create(p_dsAction);

	if (result == SUCCESS) {
		ControlManager()->Register(this);
		InputManager()->SetWorld(this);
		GameState()->StopArea(LegoGameState::e_previousArea);

		switch (GameState()->GetLoadedAct()) {
		case LegoGameState::e_act2:
			GameState()->StopArea(LegoGameState::e_act2main);
			break;
		case LegoGameState::e_act3:
			GameState()->StopArea(LegoGameState::e_act2main); // Looks like a bug
			break;
		case LegoGameState::e_actNotFound:
			m_destLocation = LegoGameState::e_infomain;
		}

		if (GameState()->m_currentArea == LegoGameState::e_isle) {
			GameState()->m_currentArea = LegoGameState::e_undefined;
		}

		LegoGameState* gameState = GameState();
		Act1State* act1state = (Act1State*) gameState->GetState("Act1State");
		if (act1state == NULL) {
			act1state = (Act1State*) gameState->CreateState("Act1State");
		}
		m_act1state = act1state;

		EnableAnimations(TRUE);
		GameState()->SetDirty(TRUE);
	}

	return result;
}

// FUNCTION: LEGO1 0x10030c10
// FUNCTION: BETA10 0x10032b63
MxLong Isle::Notify(MxParam& p_param)
{
	MxLong result = 0;
	MxNotificationParam& param = (MxNotificationParam&) p_param;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (param.GetNotification()) {
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationButtonUp:
		case c_notificationButtonDown:
			switch (m_act1state->m_unk0x018) {
			case 3:
				result = m_pizza->Notify(p_param);
				break;
			case 10:
				result = m_ambulance->Notify(p_param);
				break;
			}
			break;
		case c_notificationControl:
			result = HandleControl((LegoControlManagerNotificationParam&) p_param);
			break;
		case c_notificationEndAnim:
			switch (m_act1state->m_unk0x018) {
			case 4:
				result = UserActor()->Notify(p_param);
				break;
			case 8:
				result = m_towtrack->Notify(p_param);
				break;
			case 10:
				result = m_ambulance->Notify(p_param);
				break;
			}
			break;
		case c_notificationPathStruct:
			result = HandlePathStruct((LegoPathStructNotificationParam&) p_param);
			break;
		case c_notificationType20:
			Enable(TRUE);
			break;
		case c_notificationTransitioned:
			result = HandleTransitionEnd();
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10030d90
MxLong Isle::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	MxLong result;

	switch (m_act1state->m_unk0x018) {
	case 2:
		HandleElevatorEndAction();
		result = 1;
		break;
	case 3:
		result = m_pizza->Notify(p_param);
		break;
	case 8:
		result = m_towtrack->Notify(p_param);
		break;
	case 10:
		result = m_ambulance->Notify(p_param);
		break;
	default:
		result = m_radio.Notify(p_param);

		if (result == 0) {
			MxDSAction* action = p_param.GetAction();

			// TODO: Should be signed, but worsens match
			MxU32 script;

			if (action->GetAtomId() == *g_jukeboxScript) {
				script = action->GetObjectId();

				if (script >= JukeboxScript::c_JBMusic1 && script <= JukeboxScript::c_JBMusic6) {
					m_jukebox->StopAction((JukeboxScript::Script) script);
					result = 1;
				}
			}
			else if (m_act1state->m_planeActive) {
				script = action->GetObjectId();

				if (script >= IsleScript::c_nic002pr_RunAnim && script <= IsleScript::c_nic004pr_RunAnim) {
					m_act1state->m_planeActive = FALSE;
				}
			}
			else {
				script = action->GetObjectId();

				if (script == IsleScript::c_Avo917In_PlayWav ||
					(script >= IsleScript::c_Avo900Ps_PlayWav && script <= IsleScript::c_Avo907Ps_PlayWav)) {
					BackgroundAudioManager()->RaiseVolume();
				}
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10030ef0
void Isle::HandleElevatorEndAction()
{
	switch (m_act1state->m_elevFloor) {
	case Act1State::c_floor1:
		m_destLocation = LegoGameState::e_infomain;
		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		m_act1state->m_unk0x018 = 0;
		break;
	case Act1State::c_floor2:
		if (m_act1state->m_unk0x01e) {
			m_act1state->m_unk0x01e = FALSE;
			m_act1state->m_unk0x018 = 0;
			InputManager()->EnableInputProcessing();
		}
		else {
			InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_Floor2, NULL);
			InputManager()->EnableInputProcessing();
			m_act1state->m_unk0x01e = TRUE;
		}
		break;
	case Act1State::c_floor3:
		m_destLocation = LegoGameState::e_elevopen;
		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		m_act1state->m_unk0x018 = 0;
		break;
	}
}

// FUNCTION: LEGO1 0x10030fc0
void Isle::ReadyWorld()
{
	LegoWorld::ReadyWorld();

	if (m_act1state->GetUnknown21()) {
		GameState()->SwitchArea(LegoGameState::e_infomain);
		m_act1state->SetUnknown18(0);
		m_act1state->SetUnknown21(0);
	}
	else if (GameState()->GetLoadedAct() != LegoGameState::e_act1) {
		EnableAnimations(TRUE);
		FUN_10032620();
		m_act1state->PlaceActors();
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
	}
}

// FUNCTION: LEGO1 0x10031030
MxLong Isle::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	if (p_param.GetUnknown0x28() == 1) {
		MxDSAction action;

		switch (p_param.GetClickedObjectId()) {
		case IsleScript::c_ElevRide_Info_Ctl:
			m_act1state->m_unk0x018 = 2;

			switch (m_act1state->m_elevFloor) {
			case Act1State::c_floor1:
				m_destLocation = LegoGameState::e_infomain;
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
				break;
			case Act1State::c_floor2:
				InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_Elev2_1_Ride, NULL);
				InputManager()->DisableInputProcessing();
				break;
			case Act1State::c_floor3:
				InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_Elev3_1_Ride, NULL);
				InputManager()->DisableInputProcessing();
				break;
			}

			m_act1state->m_elevFloor = Act1State::c_floor1;
			break;
		case IsleScript::c_ElevRide_Two_Ctl:
			m_act1state->m_unk0x018 = 2;

			switch (m_act1state->m_elevFloor) {
			case Act1State::c_floor1:
				InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_Elev1_2_Ride, NULL);
				InputManager()->DisableInputProcessing();
				break;
			case Act1State::c_floor2:
				InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_Floor2, NULL);
				m_act1state->m_unk0x01e = TRUE;
				break;
			case Act1State::c_floor3:
				InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_Elev3_2_Ride, NULL);
				InputManager()->DisableInputProcessing();
				break;
			}

			m_act1state->m_elevFloor = Act1State::c_floor2;
			break;
		case IsleScript::c_ElevRide_Three_Ctl:
			m_act1state->m_unk0x018 = 2;

			switch (m_act1state->m_elevFloor) {
			case Act1State::c_floor1:
				InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_Elev1_3_Ride, NULL);
				InputManager()->DisableInputProcessing();
				break;
			case Act1State::c_floor2:
				InputManager()->DisableInputProcessing();
				InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_Elev2_3_Ride, NULL);
				break;
			case Act1State::c_floor3:
				m_destLocation = LegoGameState::e_elevopen;
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
				break;
			}

			m_act1state->m_elevFloor = Act1State::c_floor3;
			break;
		case IsleScript::c_ElevOpen_LeftArrow_Ctl:
		case IsleScript::c_ElevDown_RightArrow_Ctl:
			m_destLocation = LegoGameState::e_seaview;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case IsleScript::c_ElevOpen_RightArrow_Ctl:
		case IsleScript::c_ElevDown_LeftArrow_Ctl:
			m_destLocation = LegoGameState::e_observe;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case IsleScript::c_Observe_LeftArrow_Ctl:
			m_act1state->StopCptClickDialogue();
			m_radio.Stop();
		case IsleScript::c_SeaView_RightArrow_Ctl:
			m_destLocation = LegoGameState::e_elevopen;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case IsleScript::c_Observe_RightArrow_Ctl:
			m_act1state->StopCptClickDialogue();
			m_radio.Stop();
		case IsleScript::c_SeaView_LeftArrow_Ctl:
			m_destLocation = LegoGameState::e_elevdown;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case IsleScript::c_Observe_Plane_Ctl:
			if (!m_act1state->m_planeActive) {
				switch (rand() % 3) {
				case 0:
					InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_nic002pr_RunAnim, NULL);
					break;
				case 1:
					InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_nic003pr_RunAnim, NULL);
					break;
				case 2:
					InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_nic004pr_RunAnim, NULL);
					break;
				}

				m_act1state->m_planeActive = TRUE;
			}
			break;
		case IsleScript::c_Observe_Sun_Ctl:
			GameState()->GetBackgroundColor()->ToggleDayNight(TRUE);
			break;
		case IsleScript::c_Observe_Moon_Ctl:
			GameState()->GetBackgroundColor()->ToggleDayNight(FALSE);
			break;
		case IsleScript::c_Observe_SkyColor_Ctl:
			GameState()->GetBackgroundColor()->ToggleSkyColor();
			break;
		case IsleScript::c_Observe_LCab_Ctl:
			action.SetAtomId(*g_isleScript);
			action.SetObjectId(IsleScript::c_Observe_Monkey_Flc);
			action.SetUnknown24(0);
			Start(&action);
			break;
		case IsleScript::c_Observe_RCab_Ctl:
			UpdateGlobe();
			break;
		case IsleScript::c_Observe_GlobeLArrow_Ctl:
			UpdateLightPosition(-1);
			UpdateGlobe();
			break;
		case IsleScript::c_Observe_GlobeRArrow_Ctl:
			UpdateLightPosition(1);
			UpdateGlobe();
			break;
		case IsleScript::c_Observe_Draw1_Ctl:
		case IsleScript::c_Observe_Draw2_Ctl:
			m_act1state->PlayCptClickDialogue();
			break;
		case IsleScript::c_ElevDown_Elevator_Ctl:
			m_destLocation = LegoGameState::e_elevride2;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case IsleScript::c_PoliDoor_LeftArrow_Ctl:
		case IsleScript::c_PoliDoor_RightArrow_Ctl:
			m_destLocation = LegoGameState::e_police;
			VariableTable()->SetVariable("VISIBILITY", "Show Policsta");
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case IsleScript::c_PoliDoor_Door_Ctl:
			m_destLocation = LegoGameState::e_unk33;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case IsleScript::c_GaraDoor_LeftArrow_Ctl:
		case IsleScript::c_GaraDoor_RightArrow_Ctl:
			m_destLocation = LegoGameState::e_garage;
			VariableTable()->SetVariable("VISIBILITY", "Show Gas");
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case IsleScript::c_GaraDoor_Door_Ctl:
			m_destLocation = LegoGameState::e_unk28;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x10031590
void Isle::UpdateGlobe()
{
	MxS32 lightPosition = atoi(VariableTable()->GetVariable("lightposition"));

	for (MxS32 i = 0; i < 6; i++) {
		MxStillPresenter* presenter = (MxStillPresenter*) Find(*g_isleScript, IsleScript::c_Observe_Globe1_Bitmap + i);

		if (presenter != NULL) {
			presenter->Enable(i == lightPosition);
		}
	}
}

// FUNCTION: LEGO1 0x100315f0
// FUNCTION: BETA10 0x10033e46
MxLong Isle::HandlePathStruct(LegoPathStructNotificationParam& p_param)
{
	MxLong result = 0;

	if (UserActor() != NULL) {
		if (UserActor() == m_dunebuggy) {
			result = m_dunebuggy->Notify(p_param);
		}
		else if (UserActor() == m_motocycle) {
			result = m_motocycle->Notify(p_param);
		}
	}

	switch (m_act1state->m_unk0x018) {
	case 3:
		result = m_pizza->Notify(p_param);
		break;
	case 8:
		result = m_towtrack->Notify(p_param);
		break;
	case 10:
		result = m_ambulance->Notify(p_param);
		break;
	}

	if (result == 0) {
		// These values correspond to certain paths on the island
		switch (p_param.GetData()) {
		case 0x12c:
			AnimationManager()->FUN_10064670(NULL);
			result = 1;
			break;
		case 0x12d:
			AnimationManager()->FUN_10064880("brickstr", 0, 20000);
			result = 1;
			break;
		case 0x131:
			if (m_act1state->m_unk0x018 != 10) {
				AnimationManager()->FUN_10064740(FALSE);
			}
			result = 1;
			break;
		case 0x132:
			AnimationManager()->FUN_10064880("mama", 0, 20000);
			AnimationManager()->FUN_10064880("papa", 0, 20000);
			result = 1;
			break;
		case 0x136:
			LegoEntity* bouy = (LegoEntity*) Find("MxEntity", "bouybump");
			if (bouy != NULL) {
				NotificationManager()->Send(bouy, LegoEventNotificationParam(c_notificationClick, NULL, 0, 0, 0, 0));
			}
			result = 1;
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10031820
// FUNCTION: BETA10 0x10034158
void Isle::Enable(MxBool p_enable)
{
	if ((MxBool) m_set0xd0.empty() == p_enable) {
		return;
	}

	LegoWorld::Enable(p_enable);
	m_radio.Initialize(p_enable);

	if (p_enable) {
		CreateState();

		VideoManager()->ResetPalette(FALSE);
		m_act1state->PlaceActors();

		if (UserActor() != NULL && UserActor()->GetActorId() != LegoActor::c_none) {
			// TODO: Match, most likely an inline function
			MxS32 targetEntityId = (UserActor()->GetActorId() == 1) + 250;

			if (targetEntityId != -1) {
				InvokeAction(Extra::e_start, *g_isleScript, targetEntityId, NULL);
			}
		}

		InputManager()->SetWorld(this);
		GameState()->StopArea(LegoGameState::e_previousArea);
		GameState()->m_previousArea = GameState()->m_currentArea;

		EnableAnimations(TRUE);

		if (m_act1state->m_unk0x018 == 0) {
			MxS32 locations[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

			for (MxU32 i = 0; i < 5; i++) {
				MxS32 r = rand() % 5;

				for (MxU32 j = 0; j < sizeOfArray(locations); j++) {
					if (locations[j] != 0 && r-- == 0) {
						AnimationManager()->AddExtra(locations[j], TRUE);
						locations[j] = 0;
						break;
					}
				}
			}
		}

		if (UserActor() != NULL && UserActor()->IsA("Jetski")) {
			IslePathActor* actor = (IslePathActor*) UserActor();
			actor->SpawnPlayer(
				LegoGameState::e_unk45,
				FALSE,
				IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
			);
			actor->SetActorState(LegoPathActor::c_initial);
		}
		else {
			FUN_10032620();
		}

		switch (GameState()->m_currentArea) {
		case LegoGameState::e_elevride:
			m_destLocation = LegoGameState::e_elevride;
			NotificationManager()->Send(this, MxNotificationParam(c_notificationTransitioned, NULL));
			SetIsWorldActive(FALSE);
			break;
		case LegoGameState::e_jetrace2:
			if (((JetskiRaceState*) GameState()->GetState("JetskiRaceState"))->m_unk0x28 == 2) {
				m_act1state->m_unk0x018 = 5;
			}

			PlaceActor(UserActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationClick, NULL, 0, 0, 0, 0);
				m_jetski->Notify(param);
			}
#else
			m_jetski->Notify(LegoEventNotificationParam(c_notificationClick, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_garadoor:
			m_destLocation = LegoGameState::e_garadoor;
			NotificationManager()->Send(this, MxNotificationParam(c_notificationTransitioned, NULL));
			SetIsWorldActive(FALSE);
			break;
		case LegoGameState::e_polidoor:
			m_destLocation = LegoGameState::e_polidoor;
			NotificationManager()->Send(this, MxNotificationParam(c_notificationTransitioned, NULL));
			SetIsWorldActive(FALSE);
			break;
		case LegoGameState::e_bike:
			PlaceActor(UserActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationClick, NULL, 0, 0, 0, 0);
				m_bike->Notify(param);
			}
#else
			m_bike->Notify(LegoEventNotificationParam(c_notificationClick, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_dunecar:
			PlaceActor(UserActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationClick, NULL, 0, 0, 0, 0);
				m_dunebuggy->Notify(param);
			}
#else
			m_dunebuggy->Notify(LegoEventNotificationParam(c_notificationClick, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_motocycle:
			PlaceActor(UserActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationClick, NULL, 0, 0, 0, 0);
				m_motocycle->Notify(param);
			}
#else
			m_motocycle->Notify(LegoEventNotificationParam(c_notificationClick, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_copter:
			PlaceActor(UserActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationClick, NULL, 0, 0, 0, 0);
				m_helicopter->Notify(param);
			}
#else
			m_helicopter->Notify(LegoEventNotificationParam(c_notificationClick, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_skateboard:
			PlaceActor(UserActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationClick, NULL, 0, 0, 0, 0);
				m_skateboard->Notify(param);
			}
#else
			m_skateboard->Notify(LegoEventNotificationParam(c_notificationClick, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_jetski:
			PlaceActor(UserActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationClick, NULL, 0, 0, 0, 0);
				m_jetski->Notify(param);
			}
#else
			m_jetski->Notify(LegoEventNotificationParam(c_notificationClick, NULL, 0, 0, 0, 0));
#endif
			break;
		default:
			InputManager()->SetCamera(m_cameraController);
			SetIsWorldActive(TRUE);
			break;
		}

		switch (m_act1state->m_unk0x018) {
		case 0:
		case 1:
			m_act1state->m_unk0x018 = 0;

			if (GameState()->m_currentArea == LegoGameState::e_pizzeriaExterior) {
				AnimationManager()->FUN_10064740(NULL);
			}
			else if (GameState()->m_currentArea == LegoGameState::e_unk66) {
				Mx3DPointFloat position(UserActor()->GetROI()->GetWorldPosition());

				Mx3DPointFloat sub(-21.375f, 0.0f, -41.75f);
				sub -= position;
				if (sub.LenSquared() < 1024.0f) {
					AnimationManager()->FUN_10064740(NULL);
				}

				Mx3DPointFloat sub2(98.874992f, 0.0f, -46.156292f);
				sub2 -= position;
				if (sub2.LenSquared() < 1024.0f) {
					AnimationManager()->FUN_10064670(NULL);
				}
			}
			break;
		case 5: {
			((IslePathActor*) UserActor())
				->SpawnPlayer(
					LegoGameState::e_jetrace2,
					FALSE,
					IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
				);
			JetskiRaceState* raceState = (JetskiRaceState*) GameState()->GetState("JetskiRaceState");

			if (raceState->m_unk0x28 == 2) {
				IsleScript::Script script = IsleScript::c_noneIsle;

				switch (raceState->GetState(GameState()->GetActorId())->GetUnknown0x02()) {
				case 1:
					script = IsleScript::c_sjs014in_RunAnim;
					break;
				case 2:
					script = IsleScript::c_sjs013in_RunAnim;
					break;
				case 3:
					script = IsleScript::c_sjs012in_RunAnim;
					break;
				}

				AnimationManager()
					->FUN_10060dc0(script, NULL, TRUE, LegoAnimationManager::e_unk1, NULL, FALSE, FALSE, TRUE, FALSE);
			}

			m_act1state->m_unk0x018 = 0;
			EnableAnimations(FALSE);
			AnimationManager()->FUN_10064670(NULL);
			break;
		}
		case 6: {
			GameState()->m_currentArea = LegoGameState::e_carraceExterior;
			((IslePathActor*) UserActor())
				->SpawnPlayer(
					LegoGameState::e_unk21,
					FALSE,
					IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
				);
			CarRaceState* raceState = (CarRaceState*) GameState()->GetState("CarRaceState");

			if (raceState->m_unk0x28 == 2) {
				IsleScript::Script script = IsleScript::c_noneIsle;

				switch (raceState->GetState(GameState()->GetActorId())->GetUnknown0x02()) {
				case 1:
					script = IsleScript::c_srt003in_RunAnim;
					break;
				case 2:
					script = IsleScript::c_srt002in_RunAnim;
					break;
				case 3:
					script = IsleScript::c_srt001in_RunAnim;
					break;
				}

				AnimationManager()
					->FUN_10060dc0(script, NULL, TRUE, LegoAnimationManager::e_unk1, NULL, FALSE, FALSE, TRUE, FALSE);
			}

			m_act1state->m_unk0x018 = 0;
			EnableAnimations(TRUE);
			break;
		}
		case 7:
			m_act1state->m_unk0x018 = 8;

			AnimationManager()->FUN_1005f6d0(FALSE);
			AnimationManager()->EnableCamAnims(FALSE);

			g_isleFlags &= ~c_playMusic;
			m_towtrack->FUN_1004dab0();
			break;
		case 9:
			m_act1state->m_unk0x018 = 10;

			AnimationManager()->FUN_1005f6d0(FALSE);
			AnimationManager()->EnableCamAnims(FALSE);

			g_isleFlags &= ~c_playMusic;
			m_ambulance->FUN_10036e60();
			break;
		case 11:
			m_act1state->m_unk0x018 = 0;
			((IslePathActor*) UserActor())
				->SpawnPlayer(
					LegoGameState::e_jukeboxExterior,
					TRUE,
					IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
				);
			GameState()->m_currentArea = LegoGameState::e_unk66;
			EnableAnimations(TRUE);
			m_jukebox->StartAction();
			break;
		}

		SetAppCursor(e_cursorArrow);

		if (m_act1state->m_unk0x018 != 8 &&
			(m_act1state->m_unk0x018 != 0 || GameState()->m_currentArea != LegoGameState::e_elevride) &&
			(m_act1state->m_unk0x018 != 0 || GameState()->m_currentArea != LegoGameState::e_polidoor) &&
			(m_act1state->m_unk0x018 != 0 || GameState()->m_currentArea != LegoGameState::e_garadoor) &&
			(m_act1state->m_unk0x018 != 0 || GameState()->m_currentArea != LegoGameState::e_bike) &&
			(m_act1state->m_unk0x018 != 0 || GameState()->m_currentArea != LegoGameState::e_dunecar) &&
			(m_act1state->m_unk0x018 != 0 || GameState()->m_currentArea != LegoGameState::e_motocycle) &&
			(m_act1state->m_unk0x018 != 0 || GameState()->m_currentArea != LegoGameState::e_copter) &&
			(m_act1state->m_unk0x018 != 0 || GameState()->m_currentArea != LegoGameState::e_jetski) &&
			(m_act1state->m_unk0x018 != 0 || GameState()->m_currentArea != LegoGameState::e_skateboard) &&
			(m_act1state->m_unk0x018 != 0 || GameState()->m_currentArea != LegoGameState::e_jetrace2)) {
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		}

		SetROIVisible("stretch", FALSE);
		SetROIVisible("bird", FALSE);
		SetROIVisible("rcred", FALSE);
		SetROIVisible("towtk", FALSE);
		SetROIVisible("pizpie", FALSE);
	}
	else {
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}

		m_act1state->RemoveActors();
	}
}

// FUNCTION: LEGO1 0x10032620
void Isle::FUN_10032620()
{
	VideoManager()->Get3DManager()->SetFrustrum(90.0, 0.1, 250.0);

	switch (GameState()->m_currentArea) {
	case LegoGameState::e_unk66: {
		MxMatrix mat(UserActor()->GetROI()->GetLocal2World());
		LegoPathBoundary* boundary = UserActor()->GetBoundary();
		((IslePathActor*) UserActor())->VTable0xec(mat, boundary, TRUE);
		break;
	}
	case LegoGameState::e_unk4:
	case LegoGameState::e_jetraceExterior:
	case LegoGameState::e_unk17:
	case LegoGameState::e_carraceExterior:
	case LegoGameState::e_unk20:
	case LegoGameState::e_pizzeriaExterior:
	case LegoGameState::e_garageExterior:
	case LegoGameState::e_hospitalExterior:
	case LegoGameState::e_unk31:
	case LegoGameState::e_policeExterior:
		((IslePathActor*) UserActor())
			->SpawnPlayer(
				GameState()->m_currentArea,
				TRUE,
				IslePathActor::c_spawnBit1 | IslePathActor::c_playMusic | IslePathActor::c_spawnBit3
			);
		GameState()->m_currentArea = LegoGameState::e_unk66;
		break;
	}
}

// FUNCTION: LEGO1 0x100327a0
MxLong Isle::HandleTransitionEnd()
{
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_Avo917In_PlayWav, NULL);
	DeleteObjects(&m_atomId, IsleScript::c_Avo900Ps_PlayWav, IsleScript::c_Avo907Ps_PlayWav);

	if (m_destLocation != LegoGameState::e_skateboard) {
		m_act1state->m_unk0x018 = 0;
	}

	switch (m_destLocation) {
	case LegoGameState::e_infomain:
		((LegoEntity*) Find(*g_isleScript, IsleScript::c_InfoCenter_Entity))->GetROI()->SetVisibility(TRUE);
		GameState()->SwitchArea(m_destLocation);
		m_destLocation = LegoGameState::e_undefined;
		break;
	case LegoGameState::e_elevride:
		m_act1state->m_unk0x01f = TRUE;
		VariableTable()->SetVariable("VISIBILITY", "Hide infocen");
		FUN_10032d30(IsleScript::c_ElevRide_Background_Bitmap, JukeboxScript::c_Elevator_Music, "LCAMZI1,90", FALSE);
		break;
	case LegoGameState::e_elevride2:
		FUN_10032d30(IsleScript::c_ElevRide_Background_Bitmap, JukeboxScript::c_Elevator_Music, "LCAMZI2,90", FALSE);

		if (m_destLocation == LegoGameState::e_undefined) {
			((MxStillPresenter*) Find(m_atomId, IsleScript::c_Meter3_Bitmap))->Enable(TRUE);
		}
		break;
	case LegoGameState::e_elevopen:
		FUN_10032d30(
			IsleScript::c_ElevOpen_Background_Bitmap,
			JukeboxScript::c_InfoCenter_3rd_Floor_Music,
			"LCAMZIS,90",
			FALSE
		);
		break;
	case LegoGameState::e_seaview:
		FUN_10032d30(
			IsleScript::c_SeaView_Background_Bitmap,
			JukeboxScript::c_InfoCenter_3rd_Floor_Music,
			"LCAMZIE,90",
			FALSE
		);
		break;
	case LegoGameState::e_observe:
		FUN_10032d30(
			IsleScript::c_Observe_Background_Bitmap,
			JukeboxScript::c_InfoCenter_3rd_Floor_Music,
			"LCAMZIW,90",
			FALSE
		);
		break;
	case LegoGameState::e_elevdown:
		FUN_10032d30(
			IsleScript::c_ElevDown_Background_Bitmap,
			JukeboxScript::c_InfoCenter_3rd_Floor_Music,
			"LCAMZIN,90",
			FALSE
		);
		break;
	case LegoGameState::e_garadoor:
		m_act1state->m_unk0x01f = TRUE;
		VariableTable()->SetVariable("VISIBILITY", "Hide Gas");
		FUN_10032d30(IsleScript::c_GaraDoor_Background_Bitmap, JukeboxScript::c_JBMusic2, "LCAMZG1,90", FALSE);
		break;
	case LegoGameState::e_unk28:
		GameState()->SwitchArea(m_destLocation);
		GameState()->StopArea(LegoGameState::e_previousArea);
		m_destLocation = LegoGameState::e_undefined;
		VariableTable()->SetVariable("VISIBILITY", "Show Gas");
		AnimationManager()->Resume();
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		SetAppCursor(e_cursorArrow);
		SetIsWorldActive(TRUE);
		break;
	case LegoGameState::e_unk33:
		GameState()->SwitchArea(m_destLocation);
		GameState()->StopArea(LegoGameState::e_previousArea);
		m_destLocation = LegoGameState::e_undefined;
		VariableTable()->SetVariable("VISIBILITY", "Show Policsta");
		AnimationManager()->Resume();
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		SetAppCursor(e_cursorArrow);
		SetIsWorldActive(TRUE);
		break;
	case LegoGameState::e_polidoor:
		m_act1state->m_unk0x01f = TRUE;
		VariableTable()->SetVariable("VISIBILITY", "Hide Policsta");
		FUN_10032d30(
			IsleScript::c_PoliDoor_Background_Bitmap,
			JukeboxScript::c_PoliceStation_Music,
			"LCAMZP1,90",
			FALSE
		);
		break;
	case LegoGameState::e_bike:
		m_act1state->m_unk0x01f = TRUE;
		FUN_10032d30(IsleScript::c_BikeDashboard_Bitmap, JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_bike->ActivateSceneActions();
		}
		break;
	case LegoGameState::e_dunecar:
		m_act1state->m_unk0x01f = TRUE;
		FUN_10032d30(IsleScript::c_DuneCarFuelMeter, JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_dunebuggy->ActivateSceneActions();
		}
		break;
	case LegoGameState::e_motocycle:
		m_act1state->m_unk0x01f = TRUE;
		FUN_10032d30(IsleScript::c_MotoBikeDashboard_Bitmap, JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_motocycle->ActivateSceneActions();
		}
		break;
	case LegoGameState::e_copter:
		m_act1state->m_unk0x01f = TRUE;
		FUN_10032d30(IsleScript::c_HelicopterDashboard_Bitmap, JukeboxScript::c_MusicTheme1, NULL, TRUE);
		break;
	case LegoGameState::e_skateboard:
		m_act1state->m_unk0x01f = TRUE;
		FUN_10032d30(IsleScript::c_SkatePizza_Bitmap, JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_skateboard->ActivateSceneActions();
		}
		break;
	case LegoGameState::e_ambulance:
		m_act1state->m_unk0x01f = TRUE;
		m_act1state->m_unk0x018 = 10;
		FUN_10032d30(IsleScript::c_AmbulanceFuelMeter, JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_ambulance->ActivateSceneActions();
		}
		break;
	case LegoGameState::e_towtrack:
		m_act1state->m_unk0x01f = TRUE;
		m_act1state->m_unk0x018 = 8;
		FUN_10032d30(IsleScript::c_TowFuelMeter, JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_towtrack->ActivateSceneActions();
		}
		break;
	case LegoGameState::e_jetski:
		m_act1state->m_unk0x01f = TRUE;
		FUN_10032d30((IsleScript::Script) m_jetski->GetUnknown0x160(), JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_jetski->ActivateSceneActions();
		}
		break;
	default:
		GameState()->SwitchArea(m_destLocation);
		m_destLocation = LegoGameState::e_undefined;
	}

	return 1;
}

// FUNCTION: LEGO1 0x10032d30
void Isle::FUN_10032d30(
	IsleScript::Script p_script,
	JukeboxScript::Script p_music,
	const char* p_cameraLocation,
	MxBool p_und
)
{
	if (m_act1state->m_unk0x01f) {
		MxPresenter* presenter = (MxPresenter*) Find(m_atomId, p_script);

		if (presenter != NULL && presenter->GetCurrentTickleState() == MxPresenter::e_repeating) {
			if (p_music != JukeboxScript::c_MusicTheme1) {
				PlayMusic(p_music);
			}

			if (p_und) {
				InputManager()->SetCamera(m_cameraController);
			}
			else {
				InputManager()->SetCamera(NULL);
			}

			if (p_cameraLocation != NULL) {
				VariableTable()->SetVariable(g_varCAMERALOCATION, p_cameraLocation);
			}

			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			SetAppCursor(e_cursorArrow);
			m_destLocation = LegoGameState::e_undefined;
			m_act1state->m_unk0x01f = FALSE;
		}
		else {
			NotificationManager()->Send(this, MxNotificationParam(c_notificationTransitioned, NULL));
		}
	}
	else {
		GameState()->SwitchArea(m_destLocation);
		GameState()->StopArea(LegoGameState::e_previousArea);
		NotificationManager()->Send(this, MxNotificationParam(c_notificationTransitioned, NULL));
		m_act1state->m_unk0x01f = TRUE;
	}
}

// FUNCTION: LEGO1 0x10032f10
void Isle::Add(MxCore* p_object)
{
	LegoWorld::Add(p_object);

	if (p_object->IsA("Pizza")) {
		m_pizza = (Pizza*) p_object;
	}
	else if (p_object->IsA("Pizzeria")) {
		m_pizzeria = (Pizzeria*) p_object;
	}
	else if (p_object->IsA("TowTrack")) {
		m_towtrack = (TowTrack*) p_object;
	}
	else if (p_object->IsA("Ambulance")) {
		m_ambulance = (Ambulance*) p_object;
	}
	else if (p_object->IsA("JukeBoxEntity")) {
		m_jukebox = (JukeBoxEntity*) p_object;
	}
	else if (p_object->IsA("Helicopter")) {
		m_helicopter = (Helicopter*) p_object;
	}
	else if (p_object->IsA("Bike")) {
		m_bike = (Bike*) p_object;
	}
	else if (p_object->IsA("DuneBuggy")) {
		m_dunebuggy = (DuneBuggy*) p_object;
	}
	else if (p_object->IsA("Motorcycle")) {
		m_motocycle = (Motocycle*) p_object;
	}
	else if (p_object->IsA("SkateBoard")) {
		m_skateboard = (SkateBoard*) p_object;
	}
	else if (p_object->IsA("Jetski")) {
		m_jetski = (Jetski*) p_object;
	}
	else if (p_object->IsA("RaceCar")) {
		m_racecar = (RaceCar*) p_object;
	}
}

// FUNCTION: LEGO1 0x10033050
void Isle::VTable0x6c(LegoPathActor* p_actor)
{
	LegoWorld::Remove(p_actor);

	if (p_actor->IsA("Helicopter")) {
		m_helicopter = NULL;
	}
	else if (p_actor->IsA("DuneBuggy")) {
		m_dunebuggy = NULL;
	}
	else if (p_actor->IsA("Jetski")) {
		m_jetski = NULL;
	}
	else if (p_actor->IsA("RaceCar")) {
		m_racecar = NULL;
	}
}

// FUNCTION: LEGO1 0x100330e0
void Isle::CreateState()
{
	m_act1state = (Act1State*) GameState()->GetState("Act1State");
	if (!m_act1state) {
		m_act1state = (Act1State*) GameState()->CreateState("Act1State");
		m_act1state->m_unk0x018 = 0;
	}

	m_radio.CreateState();
	m_pizzeria->CreateState();
	m_pizza->CreateState();
	m_towtrack->CreateState();
	m_ambulance->CreateState();

	if (m_helicopter != NULL) {
		m_helicopter->CreateState();
	}
}

// FUNCTION: LEGO1 0x10033180
MxBool Isle::Escape()
{
	m_radio.Stop();
	BackgroundAudioManager()->Stop();

	switch (m_act1state->m_unk0x018) {
	case 3:
		if (UserActor() != NULL) {
			m_pizza->StopActions();
			m_pizza->FUN_100382b0();
		}
		break;
	case 8:
		if (UserActor() != NULL && !UserActor()->IsA("TowTrack")) {
			m_towtrack->StopActions();
			m_towtrack->FUN_1004dbe0();
		}
		break;
	case 10:
		if (UserActor() != NULL && !UserActor()->IsA("Ambulance")) {
			m_ambulance->StopActions();
			m_ambulance->FUN_10037250();
		}
		break;
	}

	if (m_act1state->m_unk0x01e == TRUE) {
		InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_Floor2, NULL);
		m_act1state->m_unk0x01e = FALSE;
	}

	m_act1state->m_elevFloor = Act1State::c_floor1;

	AnimationManager()->FUN_10061010(FALSE);
	DeleteObjects(&m_atomId, IsleScript::c_sba001bu_RunAnim, IsleScript::c_FNS018EN_Wav_518);

	if (UserActor()) {
		if (UserActor()->GetActorId() != GameState()->GetActorId()) {
			((IslePathActor*) UserActor())->Exit();
			m_skateboard->SetUnknown0x160(FALSE);
		}
	}

	if (GameState()->m_currentArea == LegoGameState::e_polidoor) {
		VariableTable()->SetVariable("VISIBILITY", "Show Policsta");
	}

	if (GameState()->m_currentArea == LegoGameState::e_garadoor) {
		VariableTable()->SetVariable("VISIBILITY", "Show Gas");
	}

	m_act1state->m_unk0x018 = 0;
	m_destLocation = LegoGameState::e_infomain;
	return TRUE;
}

// FUNCTION: LEGO1 0x10033350
void Isle::FUN_10033350()
{
	if (m_act1state->m_unk0x018 == 10) {
		if (UserActor() != NULL && !UserActor()->IsA("Ambulance")) {
			m_ambulance->StopActions();
			m_ambulance->FUN_10037250();
		}
	}

	if (m_act1state->m_unk0x018 == 8) {
		if (UserActor() != NULL && !UserActor()->IsA("TowTrack")) {
			m_towtrack->StopActions();
			m_towtrack->FUN_1004dbe0();
		}
	}

	if (m_act1state->m_unk0x018 == 3) {
		if (UserActor() != NULL) {
			m_pizza->StopActions();
			m_pizza->FUN_100382b0();
		}
	}

	AnimationManager()->FUN_10061010(FALSE);

	if (UserActor()) {
		if (UserActor()->GetActorId() != GameState()->GetActorId()) {
			((IslePathActor*) UserActor())->Exit();
			m_skateboard->SetUnknown0x160(FALSE);
		}
	}

	if (GameState()->m_currentArea == LegoGameState::e_polidoor) {
		VariableTable()->SetVariable("VISIBILITY", "Show Policsta");
	}

	if (GameState()->m_currentArea == LegoGameState::e_garadoor) {
		VariableTable()->SetVariable("VISIBILITY", "Show Gas");
	}

	m_destLocation = LegoGameState::e_infomain;
}

// FUNCTION: LEGO1 0x100334b0
// FUNCTION: BETA10 0x10035197
Act1State::Act1State()
{
	m_elevFloor = Act1State::c_floor1;
	m_unk0x018 = 1;
	m_unk0x01e = FALSE;
	m_cptClickDialogue = Playlist((MxU32*) g_cptClickDialogue, sizeOfArray(g_cptClickDialogue), Playlist::e_loop);
	m_unk0x01f = FALSE;
	m_planeActive = FALSE;
	m_currentCptClickDialogue = IsleScript::c_noneIsle;
	m_unk0x022 = FALSE;
	m_helicopterWindshield = NULL;
	m_helicopterJetLeft = NULL;
	m_helicopterJetRight = NULL;
	m_helicopter = NULL;
	m_jetskiFront = NULL;
	m_unk0x021 = 1;
	m_jetskiWindshield = NULL;
	m_jetski = NULL;
	m_dunebuggyFront = NULL;
	m_dunebuggy = NULL;
	m_racecarFront = NULL;
	m_racecarBack = NULL;
	m_racecarTail = NULL;
	m_racecar = NULL;
	Reset();
}

// FUNCTION: LEGO1 0x10033ac0
// FUNCTION: BETA10 0x1003524f
MxResult Act1State::Serialize(LegoFile* p_file)
{
	LegoState::Serialize(p_file);

	m_motocyclePlane.Serialize(p_file);
	m_bikePlane.Serialize(p_file);
	m_skateboardPlane.Serialize(p_file);
	m_helicopterPlane.Serialize(p_file);
	m_jetskiPlane.Serialize(p_file);
	m_dunebuggyPlane.Serialize(p_file);
	m_racecarPlane.Serialize(p_file);

	if (p_file->IsWriteMode()) {
		if (m_helicopterPlane.IsPresent()) {
			if (m_helicopterWindshield) {
				WriteNamedTexture(p_file, m_helicopterWindshield);
			}
			else {
				WriteDefaultTexture(p_file, "chwind.gif");
			}

			if (m_helicopterJetLeft) {
				WriteNamedTexture(p_file, m_helicopterJetLeft);
			}
			else {
				WriteDefaultTexture(p_file, "chjetl.gif");
			}

			if (m_helicopterJetRight) {
				WriteNamedTexture(p_file, m_helicopterJetRight);
			}
			else {
				WriteDefaultTexture(p_file, "chjetr.gif");
			}
		}

		if (m_jetskiPlane.IsPresent()) {
			if (m_jetskiFront) {
				WriteNamedTexture(p_file, m_jetskiFront);
			}
			else {
				WriteDefaultTexture(p_file, "jsfrnt.gif");
			}

			if (m_jetskiWindshield) {
				WriteNamedTexture(p_file, m_jetskiWindshield);
			}
			else {
				WriteDefaultTexture(p_file, "jswnsh.gif");
			}
		}

		if (m_dunebuggyPlane.IsPresent()) {
			if (m_dunebuggyFront) {
				WriteNamedTexture(p_file, m_dunebuggyFront);
			}
			else {
				WriteDefaultTexture(p_file, "dbfrfn.gif");
			}
		}

		if (m_racecarPlane.IsPresent()) {
			if (m_racecarFront) {
				WriteNamedTexture(p_file, m_racecarFront);
			}
			else {
				WriteDefaultTexture(p_file, "rcfrnt.gif");
			}

			if (m_racecarBack) {
				WriteNamedTexture(p_file, m_racecarBack);
			}
			else {
				WriteDefaultTexture(p_file, "rcback.gif");
			}

			if (m_racecarTail) {
				WriteNamedTexture(p_file, m_racecarTail);
			}
			else {
				WriteDefaultTexture(p_file, "rctail.gif");
			}
		}

		m_cptClickDialogue.WriteToFile(p_file);
		Write(p_file, m_unk0x022);
	}
	else if (p_file->IsReadMode()) {
		if (m_helicopterPlane.IsPresent()) {
			m_helicopterWindshield = ReadNamedTexture(p_file);
			if (m_helicopterWindshield == NULL) {
				return FAILURE;
			}

			m_helicopterJetLeft = ReadNamedTexture(p_file);
			if (m_helicopterJetLeft == NULL) {
				return FAILURE;
			}

			m_helicopterJetRight = ReadNamedTexture(p_file);
			if (m_helicopterJetRight == NULL) {
				return FAILURE;
			}
		}

		if (m_jetskiPlane.IsPresent()) {
			m_jetskiFront = ReadNamedTexture(p_file);
			if (m_jetskiFront == NULL) {
				return FAILURE;
			}

			m_jetskiWindshield = ReadNamedTexture(p_file);
			if (m_jetskiWindshield == NULL) {
				return FAILURE;
			}
		}

		if (m_dunebuggyPlane.IsPresent()) {
			m_dunebuggyFront = ReadNamedTexture(p_file);
			if (m_dunebuggyFront == NULL) {
				return FAILURE;
			}
		}

		if (m_racecarPlane.IsPresent()) {
			m_racecarFront = ReadNamedTexture(p_file);
			if (m_racecarFront == NULL) {
				return FAILURE;
			}

			m_racecarBack = ReadNamedTexture(p_file);
			if (m_racecarBack == NULL) {
				return FAILURE;
			}

			m_racecarTail = ReadNamedTexture(p_file);
			if (m_racecarTail == NULL) {
				return FAILURE;
			}
		}

		m_cptClickDialogue.ReadFromFile(p_file);
		Read(p_file, &m_unk0x022);
	}

	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10034660
void Act1State::PlayCptClickDialogue()
{
	StopCptClickDialogue();
	m_currentCptClickDialogue = (IsleScript::Script) m_cptClickDialogue.Next();
	BackgroundAudioManager()->LowerVolume();

	if (m_currentCptClickDialogue != IsleScript::c_noneIsle) {
		InvokeAction(Extra::e_start, *g_isleScript, m_currentCptClickDialogue, NULL);
	}
}

// FUNCTION: LEGO1 0x100346a0
void Act1State::StopCptClickDialogue()
{
	if (m_currentCptClickDialogue != IsleScript::c_noneIsle) {
		InvokeAction(Extra::e_stop, *g_isleScript, m_currentCptClickDialogue, NULL);
		m_currentCptClickDialogue = IsleScript::c_noneIsle;
	}
}

// FUNCTION: LEGO1 0x100346d0
MxBool Act1State::Reset()
{
	m_motocyclePlane.Reset();
	m_bikePlane.Reset();
	m_skateboardPlane.Reset();
	m_unk0x022 = FALSE;

	m_helicopterPlane.Reset();
	if (m_helicopterWindshield) {
		delete m_helicopterWindshield;
		m_helicopterWindshield = NULL;
	}

	if (m_helicopterJetLeft) {
		delete m_helicopterJetLeft;
		m_helicopterJetLeft = NULL;
	}

	if (m_helicopterJetRight) {
		delete m_helicopterJetRight;
		m_helicopterJetRight = NULL;
	}

	if (m_helicopter) {
		delete m_helicopter;
		m_helicopter = NULL;
	}

	m_jetskiPlane.Reset();
	if (m_jetskiFront) {
		delete m_jetskiFront;
		m_jetskiFront = NULL;
	}

	if (m_jetskiWindshield) {
		delete m_jetskiWindshield;
		m_jetskiWindshield = NULL;
	}

	if (m_jetski) {
		delete m_jetski;
		m_jetski = NULL;
	}

	m_dunebuggyPlane.Reset();
	if (m_dunebuggyFront) {
		delete m_dunebuggyFront;
		m_dunebuggyFront = NULL;
	}

	if (m_dunebuggy) {
		delete m_dunebuggy;
		m_dunebuggy = NULL;
	}

	m_racecarPlane.Reset();
	if (m_racecarFront) {
		delete m_racecarFront;
		m_racecarFront = NULL;
	}

	if (m_racecarBack) {
		delete m_racecarBack;
		m_racecarBack = NULL;
	}

	if (m_racecarTail) {
		delete m_racecarTail;
		m_racecarTail = NULL;
	}

	if (m_racecar) {
		delete m_racecar;
		m_racecar = NULL;
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x10034b60
void Act1State::RemoveActors()
{
	Isle* isle = (Isle*) FindWorld(*g_isleScript, IsleScript::c__Isle);

	isle->m_motocycle->UpdatePlane(m_motocyclePlane);
	isle->m_bike->UpdatePlane(m_bikePlane);
	isle->m_skateboard->UpdatePlane(m_skateboardPlane);

	if (isle->m_helicopter != NULL) {
		isle->m_helicopter->UpdatePlane(m_helicopterPlane);
		m_helicopter = isle->m_helicopter;
		isle->RemoveActor(m_helicopter);
		isle->VTable0x6c(m_helicopter);
		m_helicopter->SetBoundary(NULL);
		m_helicopter->SetController(NULL);
	}

	if (isle->m_jetski != NULL) {
		isle->m_jetski->UpdatePlane(m_jetskiPlane);
		m_jetski = isle->m_jetski;
		isle->RemoveActor(m_jetski);
		isle->VTable0x6c(m_jetski);
		m_jetski->SetBoundary(NULL);
		m_jetski->SetController(NULL);
	}

	if (isle->m_dunebuggy != NULL) {
		isle->m_dunebuggy->UpdatePlane(m_dunebuggyPlane);
		m_dunebuggy = isle->m_dunebuggy;
		isle->RemoveActor(m_dunebuggy);
		isle->VTable0x6c(m_dunebuggy);
		m_dunebuggy->SetBoundary(NULL);
		m_dunebuggy->SetController(NULL);
	}

	if (isle->m_racecar != NULL) {
		isle->m_racecar->UpdatePlane(m_racecarPlane);
		m_racecar = isle->m_racecar;
		isle->RemoveActor(m_racecar);
		isle->VTable0x6c(m_racecar);
		m_racecar->SetBoundary(NULL);
		m_racecar->SetController(NULL);
	}
}

// FUNCTION: LEGO1 0x10034d00
void Act1State::PlaceActors()
{
	Isle* isle = (Isle*) FindWorld(*g_isleScript, IsleScript::c__Isle);

	if (m_motocyclePlane.IsPresent()) {
		isle->m_motocycle->PlaceActor(m_motocyclePlane);
	}
	else {
		isle->PlaceActor(isle->m_motocycle, "INT43", 4, 0.5f, 1, 0.5f);
	}

	if (m_bikePlane.IsPresent()) {
		isle->m_bike->PlaceActor(m_bikePlane);
	}
	else {
		isle->PlaceActor(isle->m_bike, "INT44", 2, 0.5f, 0, 0.5f);
	}

	if (m_skateboardPlane.IsPresent()) {
		isle->m_skateboard->PlaceActor(m_skateboardPlane);
	}
	else {
		isle->PlaceActor(isle->m_skateboard, "EDG02_84", 4, 0.5f, 0, 0.5f);
	}

	if (m_helicopter != NULL) {
		if (!m_helicopterPlane.IsPresent()) {
			m_helicopter->SpawnPlayer(LegoGameState::e_unk40, FALSE, 0);
		}
		else {
			isle->PlaceActor(m_helicopter, m_helicopterPlane.GetName(), 0, 0.5f, 1, 0.5f);
			m_helicopter->SetLocation(
				m_helicopterPlane.GetPosition(),
				m_helicopterPlane.GetDirection(),
				m_helicopterPlane.GetUp(),
				TRUE
			);
			isle->Add(m_helicopter);
			m_helicopter->SetWorld(isle);
		}

		GetViewManager()->Add(m_helicopter->GetROI());
		m_helicopter->GetROI()->SetVisibility(TRUE);
		m_helicopterPlane.Reset();
		m_helicopter = NULL;

		if (m_helicopterWindshield != NULL) {
			FUN_1003f930(m_helicopterWindshield);
			delete m_helicopterWindshield;
			m_helicopterWindshield = NULL;
		}

		if (m_helicopterJetLeft != NULL) {
			FUN_1003f930(m_helicopterJetLeft);
			delete m_helicopterJetLeft;
			m_helicopterJetLeft = NULL;
		}

		if (m_helicopterJetRight != NULL) {
			FUN_1003f930(m_helicopterJetRight);
			delete m_helicopterJetRight;
			m_helicopterJetRight = NULL;
		}
	}

	if (m_jetski != NULL) {
		if (!m_jetskiPlane.IsPresent()) {
			m_jetski->SpawnPlayer(LegoGameState::e_unk45, FALSE, 0);
		}
		else {
			isle->PlaceActor(m_jetski, m_jetskiPlane.GetName(), 0, 0.5f, 1, 0.5f);
			m_jetski
				->SetLocation(m_jetskiPlane.GetPosition(), m_jetskiPlane.GetDirection(), m_jetskiPlane.GetUp(), TRUE);
			isle->Add(m_jetski);
			m_jetski->SetWorld(isle);
		}

		GetViewManager()->Add(m_jetski->GetROI());
		m_jetski->GetROI()->SetVisibility(TRUE);
		m_jetskiPlane.Reset();
		m_jetski = NULL;

		if (m_jetskiFront != NULL) {
			FUN_1003f930(m_jetskiFront);
			delete m_jetskiFront;
			m_jetskiFront = NULL;
		}

		if (m_jetskiWindshield != NULL) {
			FUN_1003f930(m_jetskiWindshield);
			delete m_jetskiWindshield;
			m_jetskiWindshield = NULL;
		}
	}

	if (m_dunebuggy != NULL) {
		if (!m_dunebuggyPlane.IsPresent()) {
			m_dunebuggy->SpawnPlayer(LegoGameState::e_unk43, FALSE, 0);
		}
		else {
			isle->PlaceActor(m_dunebuggy, m_dunebuggyPlane.GetName(), 0, 0.5f, 1, 0.5f);
			m_dunebuggy->SetLocation(
				m_dunebuggyPlane.GetPosition(),
				m_dunebuggyPlane.GetDirection(),
				m_dunebuggyPlane.GetUp(),
				TRUE
			);
			isle->Add(m_dunebuggy);
			m_dunebuggy->SetWorld(isle);
		}

		GetViewManager()->Add(m_dunebuggy->GetROI());
		m_dunebuggy->GetROI()->SetVisibility(TRUE);
		m_dunebuggyPlane.Reset();
		m_dunebuggy = NULL;

		if (m_dunebuggyFront != NULL) {
			FUN_1003f930(m_dunebuggyFront);
			delete m_dunebuggyFront;
			m_dunebuggyFront = NULL;
		}
	}

	if (m_racecar != NULL) {
		if (!m_racecarPlane.IsPresent()) {
			m_racecar->SpawnPlayer(LegoGameState::e_unk44, FALSE, 0);
		}
		else {
			isle->PlaceActor(m_racecar, m_racecarPlane.GetName(), 0, 0.5f, 1, 0.5f);
			m_racecar->SetLocation(
				m_racecarPlane.GetPosition(),
				m_racecarPlane.GetDirection(),
				m_racecarPlane.GetUp(),
				TRUE
			);
			isle->Add(m_racecar);
			m_racecar->SetWorld(isle);
		}

		GetViewManager()->Add(m_racecar->GetROI());
		m_racecar->GetROI()->SetVisibility(TRUE);
		m_racecarPlane.Reset();
		m_racecar = NULL;

		if (m_racecarFront != NULL) {
			FUN_1003f930(m_racecarFront);
			delete m_racecarFront;
			m_racecarFront = NULL;
		}

		if (m_racecarBack != NULL) {
			FUN_1003f930(m_racecarBack);
			delete m_racecarBack;
			m_racecarBack = NULL;
		}

		if (m_racecarTail != NULL) {
			FUN_1003f930(m_racecarTail);
			delete m_racecarTail;
			m_racecarTail = NULL;
		}
	}
}
