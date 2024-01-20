#include "police.h"

#include "jukebox.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(Police, 0x110)

// FUNCTION: LEGO1 0x1005e130
Police::Police()
{
	this->m_policeState = NULL;
	this->m_unk0x10c = 0;
	NotificationManager()->Register(this);
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
	LegoGameState* gs = GameState();
	PoliceState* p = (PoliceState*) gs->GetState("PoliceState");
	if (!p) {
		p = (PoliceState*) gs->CreateState("PoliceState");
	}

	this->m_policeState = p;
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
	FUN_10015820(0, 7);
}
