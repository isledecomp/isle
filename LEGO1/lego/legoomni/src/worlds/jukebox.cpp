#include "jukebox.h"

#include "act1state.h"
#include "jukebox_actions.h"
#include "jukeboxstate.h"
#include "jukeboxw_actions.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstillpresenter.h"
#include "mxticklemanager.h"
#include "mxtransitionmanager.h"
#include "mxvideopresenter.h"

DECOMP_SIZE_ASSERT(JukeBox, 0x104)

// FUNCTION: LEGO1 0x1005d660
JukeBox::JukeBox()
{
	m_unk0x100 = 0;
	m_state = NULL;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x1005d6e0
MxBool JukeBox::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x1005d830
JukeBox::~JukeBox()
{
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	ControlManager()->Unregister(this);
	TickleManager()->UnregisterClient(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x1005d8d0
MxResult JukeBox::Create(MxDSAction& p_dsAction)
{
	MxResult ret = LegoWorld::Create(p_dsAction);
	if (ret == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	InputManager()->SetCamera(NULL);

	m_state = (JukeBoxState*) GameState()->GetState("JukeBoxState");
	if (!m_state) {
		m_state = (JukeBoxState*) GameState()->CreateState("JukeBoxState");
		m_state->SetState(0);
	}

	GameState()->SetCurrentArea(LegoGameState::e_jukeboxw);
	GameState()->StopArea(LegoGameState::e_previousArea);
	TickleManager()->RegisterClient(this, 2000);
	return ret;
}

// FUNCTION: LEGO1 0x1005d980
MxLong JukeBox::Notify(MxParam& p_param)
{
	MxLong result = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetNotification()) {
		case c_notificationClick:
			result = HandleClick((LegoControlManagerEvent&) p_param);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(m_destLocation);
			result = 1;
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1005d9f0
void JukeBox::ReadyWorld()
{
	MxStillPresenter* presenter = NULL;

	switch (m_state->GetState()) {
	case 1:
		presenter = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
		break;
	case 2:
		presenter = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
		break;
	case 3:
		presenter = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
		break;
	case 4:
		presenter = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
		break;
	case 5:
		presenter = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
		break;
	}

	if (presenter) {
		presenter->Enable(TRUE);
	}

	m_unk0x100 = 1;
}

// FUNCTION: LEGO1 0x1005da70
MxBool JukeBox::HandleClick(LegoControlManagerEvent& p_param)
{
	MxStillPresenter* presenter;

	if (p_param.GetUnknown0x28() == 1) {
		switch (p_param.GetClickedObjectId()) {
		case JukeboxwScript::c_Dback_Ctl:
			switch (m_state->GetState()) {
			case JukeboxScript::c_MusicTheme1:
				m_state->SetState(JukeboxScript::c_ResidentalArea_Music);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeboxScript::c_MusicTheme3:
				m_state->SetState(JukeboxScript::c_MusicTheme1);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				presenter->Enable(FALSE);
				break;
			case JukeboxScript::c_Act2Cave:
				m_state->SetState(JukeboxScript::c_MusicTheme3);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeboxScript::c_BrickstrChase:
				m_state->SetState(JukeboxScript::c_Act2Cave);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeboxScript::c_BrickHunt:
				m_state->SetState(JukeboxScript::c_BrickstrChase);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeboxScript::c_ResidentalArea_Music:
				m_state->SetState(JukeboxScript::c_BrickHunt);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				presenter->Enable(TRUE);
				break;
			}
			break;
		case JukeboxwScript::c_Dfwd_Ctl:
			switch (m_state->GetState()) {
			case JukeboxScript::c_MusicTheme1:
				m_state->SetState(JukeboxScript::c_MusicTheme3);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeboxScript::c_MusicTheme3:
				m_state->SetState(JukeboxScript::c_Act2Cave);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeboxScript::c_Act2Cave:
				m_state->SetState(JukeboxScript::c_BrickstrChase);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeboxScript::c_BrickstrChase:
				m_state->SetState(JukeboxScript::c_BrickHunt);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeboxScript::c_BrickHunt:
				m_state->SetState(JukeboxScript::c_ResidentalArea_Music);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeboxScript::c_ResidentalArea_Music:
				m_state->SetState(JukeboxScript::c_MusicTheme1);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				presenter->Enable(FALSE);
				break;
			}
			break;
		case JukeboxwScript::c_Note_Ctl:
			LegoGameState* gameState = GameState();
			Act1State* act1State = (Act1State*) gameState->GetState("Act1State");
			act1State->SetUnknown18(11);
			m_destLocation = LegoGameState::Area::e_unk54;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, 0, FALSE);
			break;
		}
	}

	return TRUE;
}

// FUNCTION: LEGO1 0x1005dde0
void JukeBox::Enable(MxBool p_enable)
{
	LegoWorld::Enable(p_enable);

	if (p_enable) {
		InputManager()->SetWorld(this);
		InputManager()->SetCamera(NULL);
	}
	else {
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}
	}
}

// FUNCTION: LEGO1 0x1005de30
MxResult JukeBox::Tickle()
{
	if (m_worldStarted == FALSE) {
		LegoWorld::Tickle();
		return SUCCESS;
	}

	if (m_unk0x100 == 1) {
		m_unk0x100 = 0;
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1005de70
MxBool JukeBox::VTable0x64()
{
	m_destLocation = LegoGameState::e_infomain;
	return TRUE;
}
