#include "gasstation.h"

#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"
#include "mxticklemanager.h"

undefined4 g_unk0x100f0160;

// FUNCTION: LEGO1 0x100046a0
GasStation::GasStation()
{
	m_unk0xf8 = 0;
	m_gasStationState = NULL;
	m_unk0xfc = 0;
	m_unk0x108 = 0;
	m_unk0x104 = 0;
	m_unk0x114 = 0;
	m_unk0x106 = 0;
	m_unk0x10c = 0;
	m_unk0x115 = 0;
	m_unk0x110 = 0;

	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10004770
MxBool GasStation::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x100048c0
GasStation::~GasStation()
{
	InputManager()->UnRegister(this);
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	ControlManager()->Unregister(this);
	TickleManager()->UnregisterClient(this);
	NotificationManager()->Unregister(this);
	g_unk0x100f0160 = 3;
}

// FUNCTION: LEGO1 0x10004990
MxResult GasStation::Create(MxDSAction& p_dsAction)
{
	MxResult ret = LegoWorld::Create(p_dsAction);
	if (ret == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	InputManager()->SetCamera(NULL);

	m_gasStationState = (GasStationState*) GameState()->GetState("GasStationState");
	if (!m_gasStationState) {
		m_gasStationState = (GasStationState*) GameState()->CreateState("GasStationState");
		m_gasStationState->SetUnknown0x14(1);
	}
	else {
		if (m_gasStationState->GetUnknown0x14() != 4) {
			m_gasStationState->SetUnknown0x14(3);
		}
	}

	GameState()->SetCurrentArea(LegoGameState::e_garage);
	GameState()->StopArea(LegoGameState::e_previousArea);

	InputManager()->Register(this);
	SetIsWorldActive(FALSE);
	return ret;
}

// STUB: LEGO1 0x10004a60
MxLong GasStation::Notify(MxParam& p_param)
{
	// TODO

	return 0;
}

// STUB: LEGO1 0x10004b30
void GasStation::ReadyWorld()
{
	// TODO
}

// FUNCTION: LEGO1 0x10005c40
void GasStation::Enable(MxBool p_enable)
{
	LegoWorld::Enable(p_enable);

	if (p_enable) {
		InputManager()->SetWorld(this);
		InputManager()->SetCamera(NULL);
		return;
	}
	else {
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}
	}
}

// STUB: LEGO1 0x10005c90
MxResult GasStation::Tickle()
{
	// TODO

	return 0;
}

// STUB: LEGO1 0x10005e70
MxBool GasStation::VTable0x64()
{
	// TODO
	return FALSE;
}
