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

	m_unk0x0c = TRUE;
	CreateRadioState();
}

// STUB: LEGO1 0x1002c990
Radio::~Radio()
{
}

// STUB: LEGO1 0x1002ca30
MxLong Radio::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x1002cdc0
void Radio::Initialize(MxBool p_und)
{
	if (m_unk0x0c != p_und) {
		m_unk0x0c = p_und;
		CreateRadioState();
	}
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
