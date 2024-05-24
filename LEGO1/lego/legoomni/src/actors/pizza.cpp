#include "pizza.h"

#include "act1state.h"
#include "legogamestate.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "pizzamissionstate.h"

DECOMP_SIZE_ASSERT(Pizza, 0x9c)

// FUNCTION: LEGO1 0x10037ef0
Pizza::Pizza()
{
	m_state = NULL;
	m_unk0x80 = 0;
	m_skateboard = NULL;
	m_act1state = NULL;
	m_unk0x8c = -1;
	m_unk0x98 = 0;
	m_unk0x90 = 0x80000000;
}

// FUNCTION: LEGO1 0x10038100
Pizza::~Pizza()
{
	TickleManager()->UnregisterClient(this);
}

// STUB: LEGO1 0x10038170
MxResult Pizza::Create(MxDSAction& p_dsAction)
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100381b0
void Pizza::CreateState()
{
	m_state = (PizzaMissionState*) GameState()->GetState("PizzaMissionState");
	if (m_state == NULL) {
		m_state = (PizzaMissionState*) GameState()->CreateState("PizzaMissionState");
	}

	m_act1state = (Act1State*) GameState()->GetState("Act1State");
	if (m_act1state == NULL) {
		m_act1state = (Act1State*) GameState()->CreateState("Act1State");
	}
}

// STUB: LEGO1 0x100382b0
void Pizza::FUN_100382b0()
{
}

// STUB: LEGO1 0x10038380
void Pizza::FUN_10038380()
{
}

// STUB: LEGO1 0x100383f0
undefined4 Pizza::VTable0x68()
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100384f0
undefined4 Pizza::VTable0x80(MxParam&)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100388a0
MxResult Pizza::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10038b10
undefined4 Pizza::HandleEndAction(MxEndActionNotificationParam&)
{
	// TODO
	return 0;
}
