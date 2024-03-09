#include "elevatorbottom.h"

#include "act1state.h"
#include "jukebox.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "legovariables.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(ElevatorBottom, 0xfc)

// FUNCTION: LEGO1 0x10017e90
ElevatorBottom::ElevatorBottom()
{
	NotificationManager()->Register(this);
	this->m_unk0xf8 = LegoGameState::e_noArea;
}

// FUNCTION: LEGO1 0x10018060
ElevatorBottom::~ElevatorBottom()
{
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}
	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x100180f0
MxResult ElevatorBottom::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	SetIsWorldActive(FALSE);

	GameState()->SetCurrentArea(LegoGameState::e_elevbott);
	GameState()->StopArea(LegoGameState::e_previousArea);

	return result;
}

// FUNCTION: LEGO1 0x10018150
MxLong ElevatorBottom::Notify(MxParam& p_param)
{
	MxLong ret = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetType()) {
		case c_notificationClick:
			ret = HandleClick((LegoControlManagerEvent&) p_param);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(m_unk0xf8);
			break;
		}
	}

	return ret;
}

// FUNCTION: LEGO1 0x100181b0
void ElevatorBottom::ReadyWorld()
{
	LegoWorld::ReadyWorld();
	PlayMusic(JukeBox::e_informationCenter);
	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x100181d0
MxLong ElevatorBottom::HandleClick(LegoControlManagerEvent& p_param)
{
	MxLong result = 0;

	if (p_param.GetUnknown0x28() == 1) {
		switch (p_param.GetClickedObjectId()) {
		case 1:
			m_unk0xf8 = LegoGameState::e_infodoor;
			TransitionManager()->StartTransition(MxTransitionManager::e_pixelation, 50, FALSE, FALSE);
			result = 1;
			break;
		case 2:
			m_unk0xf8 = LegoGameState::e_infomain;
			TransitionManager()->StartTransition(MxTransitionManager::e_pixelation, 50, FALSE, FALSE);
			result = 1;
			break;
		case 3:
			LegoGameState* gs = GameState();
			Act1State* state = (Act1State*) gs->GetState("Act1State");

			if (state == NULL) {
				state = (Act1State*) gs->CreateState("Act1State");
			}

			state->SetUnknown1c(1);
			m_unk0xf8 = LegoGameState::e_elevride;
			TransitionManager()->StartTransition(MxTransitionManager::e_pixelation, 50, FALSE, FALSE);
			VariableTable()->SetVariable(g_varCAMERALOCATION, "LCAMZI1,90");
			result = 1;
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100182c0
void ElevatorBottom::Enable(MxBool p_enable)
{
	LegoWorld::Enable(p_enable);

	if (p_enable) {
		InputManager()->SetWorld(this);
		SetIsWorldActive(FALSE);
	}
	else {
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}
	}
}

// FUNCTION: LEGO1 0x10018310
MxBool ElevatorBottom::VTable0x64()
{
	DeleteObjects(&m_atom, 500, 999);
	m_unk0xf8 = LegoGameState::e_infomain;
	return TRUE;
}
