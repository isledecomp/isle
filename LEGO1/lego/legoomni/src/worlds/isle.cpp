#include "isle.h"

#include "act1state.h"
#include "ambulance.h"
#include "bike.h"
#include "carracestate.h"
#include "dunebuggy.h"
#include "helicopter.h"
#include "isle_actions.h"
#include "islepathactor.h"
#include "jetski.h"
#include "jetskiracestate.h"
#include "jukebox_actions.h"
#include "jukeboxentity.h"
#include "legoanimationmanager.h"
#include "legocontrolmanager.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "legoutils.h"
#include "legovariables.h"
#include "legovideomanager.h"
#include "misc.h"
#include "motocycle.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstillpresenter.h"
#include "mxtransitionmanager.h"
#include "pizza.h"
#include "skateboard.h"
#include "towtrack.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(Isle, 0x140);

// GLOBAL: LEGO1 0x100f1198
undefined4 g_unk0x100f1198 = 0x7f;

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

	if (CurrentActor() != NULL) {
		VTable0x6c(CurrentActor());
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

		if (GameState()->GetCurrentArea() == LegoGameState::e_isle) {
			GameState()->SetCurrentArea(LegoGameState::e_undefined);
		}

		LegoGameState* gameState = GameState();
		Act1State* state = (Act1State*) gameState->GetState("Act1State");
		if (state == NULL) {
			state = (Act1State*) gameState->CreateState("Act1State");
		}
		m_act1state = state;

		FUN_1003ef00(TRUE);
		GameState()->SetDirty(TRUE);
	}

	return result;
}

// FUNCTION: LEGO1 0x10030c10
MxLong Isle::Notify(MxParam& p_param)
{
	MxLong result = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetNotification()) {
		case c_notificationEndAction:
			result = StopAction(p_param);
			break;
		case c_notificationButtonUp:
		case c_notificationButtonDown:
			switch (m_act1state->GetUnknown18()) {
			case 3:
				result = m_pizza->Notify(p_param);
				break;
			case 10:
				result = m_ambulance->Notify(p_param);
				break;
			}
			break;
		case c_notificationClick:
			result = HandleClick(p_param);
			break;
		case c_notificationType18:
			switch (m_act1state->GetUnknown18()) {
			case 4:
				result = CurrentActor()->Notify(p_param);
				break;
			case 8:
				result = m_towtrack->Notify(p_param);
				break;
			case 10:
				result = m_ambulance->Notify(p_param);
				break;
			}
			break;
		case c_notificationType19:
			result = HandleType19Notification(p_param);
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

// STUB: LEGO1 0x10030d90
MxLong Isle::StopAction(MxParam& p_param)
{
	return 0;
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
		FUN_1003ef00(TRUE);
		FUN_10032620();
		m_act1state->FUN_10034d00();
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
	}
}

// STUB: LGEO1 0x10031030
MxLong Isle::HandleClick(MxParam& p_param)
{
	return 0;
}

// STUB: LEGO1 0x100315f0
MxLong Isle::HandleType19Notification(MxParam& p_param)
{
	return 0;
}

// FUNCTION: LEGO1 0x10031820
void Isle::Enable(MxBool p_enable)
{
	if (m_set0xd0.empty() == p_enable) {
		return;
	}

	LegoWorld::Enable(p_enable);
	m_radio.Initialize(p_enable);

	if (p_enable) {
		FUN_100330e0();

		VideoManager()->ResetPalette(FALSE);
		m_act1state->FUN_10034d00();

		if (CurrentActor() != NULL && CurrentActor()->GetActorId() != 0) {
			// TODO: Match, most likely an inline function
			MxS32 targetEntityId = (CurrentActor()->GetActorId() == 1) + 250;

			if (targetEntityId != -1) {
				InvokeAction(Extra::e_start, *g_isleScript, targetEntityId, NULL);
			}
		}

		InputManager()->SetWorld(this);
		GameState()->StopArea(LegoGameState::e_previousArea);
		GameState()->m_previousArea = GameState()->m_currentArea;

		FUN_1003ef00(TRUE);

		if (m_act1state->m_unk0x018 == 0) {
			MxU32 und[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

			for (MxU32 i = 0; i < 5; i++) {
				MxS32 und2 = rand() % 5;

				for (MxU32 j = 0; j < _countof(und); j++) {
					if (und[j] != 0 && und2-- == 0) {
						AnimationManager()->FUN_100629b0(und[j], TRUE);
						und[j] = 0;
						break;
					}
				}
			}
		}

		if (CurrentActor() != NULL && CurrentActor()->IsA("Jetski")) {
			IslePathActor* actor = CurrentActor();
			actor->VTable0xe8(LegoGameState::e_unk45, FALSE, 7);
			actor->SetUnknownDC(0);
		}
		else {
			FUN_10032620();
		}

		switch (GameState()->m_currentArea) {
		case LegoGameState::e_elevride:
			m_destLocation = LegoGameState::e_elevride;

#ifdef COMPAT_MODE
			{
				MxNotificationParam param(c_notificationTransitioned, NULL);
				NotificationManager()->Send(this, &param);
			}
#else
			NotificationManager()->Send(this, &MxNotificationParam(c_notificationTransitioned, NULL));
#endif

			SetIsWorldActive(FALSE);
			break;
		case LegoGameState::e_jetrace2:
			if (((JetskiRaceState*) GameState()->GetState("JetskiRaceState"))->GetUnknown0x28() == 2) {
				m_act1state->m_unk0x018 = 5;
			}

			FUN_1001fa70(CurrentActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationType11, NULL, 0, 0, 0, 0);
				m_jetski->Notify(param);
			}
#else
			m_jetski->Notify(LegoEventNotificationParam(c_notificationType11, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_garadoor:
			m_destLocation = LegoGameState::e_garadoor;

#ifdef COMPAT_MODE
			{
				MxNotificationParam param(c_notificationTransitioned, NULL);
				NotificationManager()->Send(this, &param);
			}
#else
			NotificationManager()->Send(this, &MxNotificationParam(c_notificationTransitioned, NULL));
#endif

			SetIsWorldActive(FALSE);
			break;
		case LegoGameState::e_polidoor:
			m_destLocation = LegoGameState::e_polidoor;

#ifdef COMPAT_MODE
			{
				MxNotificationParam param(c_notificationTransitioned, NULL);
				NotificationManager()->Send(this, &param);
			}
#else
			NotificationManager()->Send(this, &MxNotificationParam(c_notificationTransitioned, NULL));
#endif

			SetIsWorldActive(FALSE);
			break;
		case LegoGameState::e_bike:
			FUN_1001fa70(CurrentActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationType11, NULL, 0, 0, 0, 0);
				m_bike->Notify(param);
			}
#else
			m_bike->Notify(LegoEventNotificationParam(c_notificationType11, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_dunecar:
			FUN_1001fa70(CurrentActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationType11, NULL, 0, 0, 0, 0);
				m_dunebuggy->Notify(param);
			}
#else
			m_dunebuggy->Notify(LegoEventNotificationParam(c_notificationType11, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_motocycle:
			FUN_1001fa70(CurrentActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationType11, NULL, 0, 0, 0, 0);
				m_motocycle->Notify(param);
			}
#else
			m_motocycle->Notify(LegoEventNotificationParam(c_notificationType11, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_copter:
			FUN_1001fa70(CurrentActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationType11, NULL, 0, 0, 0, 0);
				m_helicopter->Notify(param);
			}
#else
			m_helicopter->Notify(LegoEventNotificationParam(c_notificationType11, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_skateboard:
			FUN_1001fa70(CurrentActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationType11, NULL, 0, 0, 0, 0);
				m_skateboard->Notify(param);
			}
#else
			m_skateboard->Notify(LegoEventNotificationParam(c_notificationType11, NULL, 0, 0, 0, 0));
#endif
			break;
		case LegoGameState::e_jetski:
			FUN_1001fa70(CurrentActor());
			SetIsWorldActive(TRUE);

#ifdef COMPAT_MODE
			{
				LegoEventNotificationParam param(c_notificationType11, NULL, 0, 0, 0, 0);
				m_jetski->Notify(param);
			}
#else
			m_jetski->Notify(LegoEventNotificationParam(c_notificationType11, NULL, 0, 0, 0, 0));
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
				AnimationManager()->FUN_10064740(FALSE);
			}
			else if (GameState()->m_currentArea == LegoGameState::e_unk66) {
				Mx3DPointFloat position(CurrentActor()->GetROI()->GetWorldPosition());

				Mx3DPointFloat sub(-21.375f, 0.0f, -41.75f);
				sub.Sub(&position);
				if (NORMSQRD3(sub) < 1024.0f) {
					AnimationManager()->FUN_10064740(FALSE);
				}

				Mx3DPointFloat sub2(98.874992f, 0.0f, -46.156292f);
				sub2.Sub(&position);
				if (NORMSQRD3(sub2) < 1024.0f) {
					AnimationManager()->FUN_10064670(FALSE);
				}
			}
			break;
		case 5: {
			CurrentActor()->VTable0xe8(LegoGameState::e_jetrace2, FALSE, 7);
			JetskiRaceState* raceState = (JetskiRaceState*) GameState()->GetState("JetskiRaceState");

			if (raceState->GetUnknown0x28() == 2) {
				undefined4 und = -1;

				switch (raceState->GetState(GameState()->GetActorId())->GetUnknown0x02()) {
				case 1:
					und = 0x35e;
					break;
				case 2:
					und = 0x35d;
					break;
				case 3:
					und = 0x35c;
					break;
				}

				AnimationManager()->FUN_10060dc0(und, 0, 1, 1, 0, 0, 0, 1, 0);
			}

			m_act1state->m_unk0x018 = 0;
			FUN_1003ef00(FALSE);
			AnimationManager()->FUN_10064670(FALSE);
			break;
		}
		case 6: {
			GameState()->m_currentArea = LegoGameState::e_carraceExterior;
			CurrentActor()->VTable0xe8(LegoGameState::e_unk21, FALSE, 7);
			CarRaceState* raceState = (CarRaceState*) GameState()->GetState("CarRaceState");

			if (raceState->GetUnknown0x28() == 2) {
				undefined4 und = -1;

				switch (raceState->GetState(GameState()->GetActorId())->GetUnknown0x02()) {
				case 1:
					und = 0x362;
					break;
				case 2:
					und = 0x361;
					break;
				case 3:
					und = 0x360;
					break;
				}

				AnimationManager()->FUN_10060dc0(und, 0, 1, 1, 0, 0, 0, 1, 0);
			}

			m_act1state->m_unk0x018 = 0;
			FUN_1003ef00(TRUE);
			break;
		}
		case 7:
			m_act1state->m_unk0x018 = 8;

			AnimationManager()->FUN_1005f6d0(FALSE);
			AnimationManager()->FUN_1005f700(FALSE);

			g_unk0x100f1198 &= ~c_bit7;
			m_towtrack->FUN_1004dab0();
			break;
		case 9:
			m_act1state->m_unk0x018 = 10;

			AnimationManager()->FUN_1005f6d0(FALSE);
			AnimationManager()->FUN_1005f700(FALSE);

			g_unk0x100f1198 &= ~c_bit7;
			m_ambulance->FUN_10036e60();
			break;
		case 11:
			m_act1state->m_unk0x018 = 0;
			CurrentActor()->VTable0xe8(LegoGameState::e_unk54, TRUE, 7);
			GameState()->m_currentArea = LegoGameState::e_unk66;
			FUN_1003ef00(TRUE);
			m_jukebox->StartAction();
			break;
		}

		SetAppCursor(0);

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

		SetROIUnknown0x0c("stretch", 0);
		SetROIUnknown0x0c("bird", 0);
		SetROIUnknown0x0c("rcred", 0);
		SetROIUnknown0x0c("towtk", 0);
		SetROIUnknown0x0c("pizpie", 0);
	}
	else {
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}

		m_act1state->FUN_10034b60();
	}
}

// FUNCTION: LEGO1 0x10032620
void Isle::FUN_10032620()
{
	VideoManager()->Get3DManager()->SetFrustrum(90.0, 0.1, 250.0);

	switch (GameState()->m_currentArea) {
	case LegoGameState::e_unk66: {
		MxMatrix mat(CurrentActor()->GetROI()->GetLocal2World());
		MxU32 unk0x88 = CurrentActor()->GetUnknown88();
		CurrentActor()->VTable0xec(mat, unk0x88, TRUE);
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
		CurrentActor()->VTable0xe8(GameState()->m_currentArea, TRUE, 7);
		GameState()->m_currentArea = LegoGameState::e_unk66;
		break;
	}
}

// FUNCTION: LEGO1 0x100327a0
MxLong Isle::HandleTransitionEnd()
{
	InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_Avo917In_PlayWav, NULL);
	DeleteObjects(&m_atom, IsleScript::c_Avo900Ps_PlayWav, IsleScript::c_Avo907Ps_PlayWav);

	if (m_destLocation != LegoGameState::e_skateboard) {
		m_act1state->m_unk0x018 = 0;
	}

	switch (m_destLocation) {
	case LegoGameState::e_infomain:
		((LegoEntity*) Find(*g_isleScript, IsleScript::c_InfoCenter_Entity))->GetROI()->SetUnknown0x0c(1);
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
			((MxStillPresenter*) Find(m_atom, IsleScript::c_Meter3_Bitmap))->Enable(TRUE);
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
		AnimationManager()->FUN_1005f0b0();
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		SetAppCursor(0);
		SetIsWorldActive(TRUE);
		break;
	case LegoGameState::e_unk33:
		GameState()->SwitchArea(m_destLocation);
		GameState()->StopArea(LegoGameState::e_previousArea);
		m_destLocation = LegoGameState::e_undefined;
		VariableTable()->SetVariable("VISIBILITY", "Show Policsta");
		AnimationManager()->FUN_1005f0b0();
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		SetAppCursor(0);
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
			m_bike->FUN_10076b60();
		}
		break;
	case LegoGameState::e_dunecar:
		m_act1state->m_unk0x01f = TRUE;
		FUN_10032d30(IsleScript::c_DuneCarFuelMeter, JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_dunebuggy->FUN_10068350();
		}
		break;
	case LegoGameState::e_motocycle:
		m_act1state->m_unk0x01f = TRUE;
		FUN_10032d30(IsleScript::c_MotoBikeDashboard_Bitmap, JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_motocycle->FUN_10035e10();
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
			m_skateboard->FUN_10010510();
		}
		break;
	case LegoGameState::e_ambulance:
		m_act1state->m_unk0x01f = TRUE;
		m_act1state->m_unk0x018 = 10;
		FUN_10032d30(IsleScript::c_AmbulanceFuelMeter, JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_ambulance->FUN_10037060();
		}
		break;
	case LegoGameState::e_towtrack:
		m_act1state->m_unk0x01f = TRUE;
		m_act1state->m_unk0x018 = 8;
		FUN_10032d30(IsleScript::c_TowFuelMeter, JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_towtrack->FUN_1004dad0();
		}
		break;
	case LegoGameState::e_jetski:
		m_act1state->m_unk0x01f = TRUE;
		FUN_10032d30((IsleScript::Script) m_jetski->GetUnknown0x160(), JukeboxScript::c_MusicTheme1, NULL, TRUE);

		if (!m_act1state->m_unk0x01f) {
			m_jetski->FUN_1007e990();
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
		MxPresenter* presenter = (MxPresenter*) Find(m_atom, p_script);

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
			SetAppCursor(0);
			m_destLocation = LegoGameState::e_undefined;
			m_act1state->m_unk0x01f = FALSE;
		}
		else {
#ifdef COMPAT_MODE
			{
				MxNotificationParam param(c_notificationTransitioned, NULL);
				NotificationManager()->Send(this, &param);
			}
#else
			NotificationManager()->Send(this, &MxNotificationParam(c_notificationTransitioned, NULL));
#endif
		}
	}
	else {
		GameState()->SwitchArea(m_destLocation);
		GameState()->StopArea(LegoGameState::e_previousArea);

#ifdef COMPAT_MODE
		{
			MxNotificationParam param(c_notificationTransitioned, NULL);
			NotificationManager()->Send(this, &param);
		}
#else
		NotificationManager()->Send(this, &MxNotificationParam(c_notificationTransitioned, NULL));
#endif

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
void Isle::VTable0x6c(IslePathActor* p_actor)
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

// STUB: LEGO1 0x100330e0
void Isle::FUN_100330e0()
{
	// TODO
}

// STUB: LEGO1 0x10033180
MxBool Isle::VTable0x64()
{
	// TODO
	return FALSE;
}
