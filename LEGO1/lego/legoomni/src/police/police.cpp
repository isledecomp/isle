#include "police.h"

#include "jukebox.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(Police, 0x110)

// FUNCTION: LEGO1 0x1005e130
Police::Police()
{
	m_policeState = NULL;
	m_unk0x10c = 0;
	NotificationManager()->Register(this);
}

// STUB: LEGO1 0x1005e1d0
MxBool Police::VTable0x5c()
{
	// TODO
	return FALSE;
}

// FUNCTION: LEGO1 0x1005e320
Police::~Police()
{
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	ControlManager()->Unregister(this);
	InputManager()->UnRegister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x1005e3e0
MxResult Police::Create(MxDSAction& p_dsAction)
{
	MxResult ret = LegoWorld::Create(p_dsAction);
	if (ret == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	SetIsWorldActive(FALSE);
	InputManager()->Register(this);

	LegoGameState* gameState = GameState();
	PoliceState* policeState = (PoliceState*) gameState->GetState("PoliceState");
	if (!policeState) {
		policeState = (PoliceState*) gameState->CreateState("PoliceState");
	}

	m_policeState = policeState;
	GameState()->SetUnknown424(0x22);
	GameState()->FUN_1003a720(0);
	return ret;
}

// STUB: LEGO1 0x1005e480
MxLong Police::Notify(MxParam& p_param)
{
	// TODO

	return 0;
}

// FUNCTION: LEGO1 0x1005e530
void Police::VTable0x50()
{
	LegoWorld::VTable0x50();
	PlayMusic(JukeBox::e_policeStation);
	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// STUB: LEGO1 0x1005e740
void Police::VTable0x68(MxBool p_add)
{
	// TODO
}

// STUB: LEGO1 0x1005e790
MxBool Police::VTable0x64()
{
	// TODO
	return FALSE;
}
