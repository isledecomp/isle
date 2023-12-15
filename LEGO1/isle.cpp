#include "isle.h"

#include "act1state.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "legoutil.h"
#include "mxnotificationmanager.h"
#include "mxtransitionmanager.h"

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
		VTable0x6c((MxCore*) GetCurrentVehicle());
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

		undefined4 currentact = GameState()->GetCurrentAct();
		if (currentact == -1) {
			m_unk0x13c = 2;
		}
		else if (currentact == 1 || currentact == 2) {
			GameState()->FUN_1003a720(0x2e);
		}

		if (GameState()->GetUnknown424() == 1) {
			GameState()->SetUnknown424(0);
		}

		Act1State* state = (Act1State*) GameState()->GetState("Act1State");
		if (state == NULL) {
			state = (Act1State*) GameState()->CreateState("Act1State");
		}
		m_act1state = state;

		FUN_1003ef0(TRUE);
		GameState()->SetDirty(TRUE);
	}

	return result;
}

// STUB: LEGO1 0x10030fc0
void Isle::Stop()
{
	// TODO
}

// STUB: LEGO1 0x10031820
void Isle::VTable0x68(MxBool p_add)
{
	// TODO
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

// STUB: LEGO1 0x10033180
MxBool Isle::VTable0x64()
{
	// TODO
	return FALSE;
}

// FUNCTION: LEGO1 0x10033050
void Isle::VTable0x6c(MxCore* p_object)
{
	LegoWorld::EndAction(p_object);

	if (p_object->IsA("Helicopter")) {
		m_helicopter = NULL;
	}
	else if (p_object->IsA("DuneBuggy")) {
		m_dunebuggy = NULL;
	}
	else if (p_object->IsA("Jetski")) {
		m_jetski = 0;
	}
	else if (p_object->IsA("RaceCar")) {
		m_racecar = 0;
	}
}
