#include "radio.h"

#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(Radio, 0x10);

// FUNCTION: LEGO1 0x1002c850
Radio::Radio()
{
	NotificationManager()->Register(this);
	ControlManager()->Register(this);

	m_unk0xc = TRUE;
	CreateRadioState();
}

// STUB: LEGO1 0x1002c990
Radio::~Radio()
{
	// TODO
}

// FUNCTION: LEGO1 0x1002cde0
void Radio::CreateRadioState()
{
	LegoGameState* gameState = GameState();
	RadioState* state = (RadioState*) gameState->GetState("RadioState");
	if (state == NULL) {
		state = (RadioState*) gameState->CreateState("RadioState");
	}

	m_state = state;
}
