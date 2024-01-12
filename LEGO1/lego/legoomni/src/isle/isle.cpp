#include "isle.h"

#include "act1state.h"
#include "ambulance.h"
#include "islepathactor.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "legoutil.h"
#include "mxnotificationmanager.h"
#include "mxtransitionmanager.h"
#include "pizza.h"
#include "towtrack.h"

DECOMP_SIZE_ASSERT(Isle, 0x140);

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
	m_motorcycle = NULL;
	m_skateboard = NULL;
	m_racecar = NULL;
	m_jetski = NULL;
	m_act1state = 0;
	m_unk0x13c = 0;

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

	if (GetCurrentVehicle() != NULL) {
		VTable0x6c(GetCurrentVehicle());
	}

	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10030b20
MxResult Isle::Create(MxDSObject& p_dsObject)
{
	GameState()->FUN_1003ceb0();

	MxResult result = LegoWorld::SetAsCurrentWorld(p_dsObject);
	if (result == SUCCESS) {
		ControlManager()->Register(this);
		InputManager()->SetWorld(this);
		GameState()->FUN_1003a720(0);

		switch (GameState()->GetCurrentAct()) {
		case 1:
			GameState()->FUN_1003a720(0x2e);
			break;
		case 2:
			GameState()->FUN_1003a720(0x2e);
			break;
		case -1:
			m_unk0x13c = 2;
		}

		if (GameState()->GetUnknown424() == 1) {
			GameState()->SetUnknown424(0);
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
		case TYPE17:
			result = HandleType17Notification(p_param);
			break;
		case TYPE18:
			switch (m_act1state->GetUnknown18()) {
			case 4:
				result = GetCurrentVehicle()->Notify(p_param);
				break;
			case 8:
				result = m_towtrack->Notify(p_param);
				break;
			case 10:
				result = m_ambulance->Notify(p_param);
				break;
			}
			break;
		case TYPE19:
			result = HandleType19Notification(p_param);
			break;
		case TYPE20:
			VTable0x68(TRUE);
			break;
		case MXTRANSITIONMANAGER_TRANSITIONENDED:
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

// STUB: LEGO1 0x10030fc0
void Isle::VTable0x50()
{
	// TODO
}

// STUB: LGEO1 0x10031030
MxLong Isle::HandleType17Notification(MxParam& p_param)
{
	return 0;
}

// STUB: LEGO1 0x100315f0
MxLong Isle::HandleType19Notification(MxParam& p_param)
{
	return 0;
}

// STUB: LEGO1 0x10031820
void Isle::VTable0x68(MxBool p_add)
{
	// TODO
}

// STUB: LEGO1 0x100327a0
MxLong Isle::HandleTransitionEnd()
{
	return 0;
}

// FUNCTION: LEGO1 0x10032f10
void Isle::VTable0x58(MxCore* p_object)
{
	LegoWorld::VTable0x58(p_object);

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
		m_motorcycle = (Motorcycle*) p_object;
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
	LegoWorld::EndAction(p_actor);

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

// STUB: LEGO1 0x10033180
MxBool Isle::VTable0x64()
{
	// TODO
	return FALSE;
}
