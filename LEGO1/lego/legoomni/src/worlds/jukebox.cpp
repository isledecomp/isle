#include "jukebox.h"

#include "isle.h"
#include "jukebox_actions.h"
#include "jukeboxw_actions.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legomain.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstillpresenter.h"
#include "mxticklemanager.h"
#include "mxtransitionmanager.h"
#include "mxvideopresenter.h"

DECOMP_SIZE_ASSERT(JukeBox, 0x104)
DECOMP_SIZE_ASSERT(JukeBoxState, 0x10)

// FUNCTION: LEGO1 0x1005d660
JukeBox::JukeBox()
{
	m_unk0x100 = 0;
	m_state = NULL;
	NotificationManager()->Register(this);
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
		m_state->m_music = JukeBoxState::e_pasquell;
	}

	GameState()->m_currentArea = LegoGameState::e_jukeboxw;
	GameState()->StopArea(LegoGameState::e_previousArea);
	TickleManager()->RegisterClient(this, 2000);
	return ret;
}

// FUNCTION: LEGO1 0x1005d980
// FUNCTION: BETA10 0x10037daf
MxLong JukeBox::Notify(MxParam& p_param)
{
	MxLong result = 0;
	MxNotificationParam& param = (MxNotificationParam&) p_param;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (param.GetNotification()) {
		case c_notificationControl:
			result = HandleControl((LegoControlManagerNotificationParam&) p_param);
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
// FUNCTION: BETA10 0x10037e39
void JukeBox::ReadyWorld()
{
	MxStillPresenter* presenter = NULL;

	switch (m_state->m_music) {
	case JukeBoxState::e_pasquell:
		break;
	case JukeBoxState::e_right:
		presenter = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
		break;
	case JukeBoxState::e_decal:
		presenter = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
		break;
	case JukeBoxState::e_wallis:
		presenter = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
		break;
	case JukeBoxState::e_nelson:
		presenter = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
		break;
	case JukeBoxState::e_torpedos:
		presenter = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
		break;
	}

	if (presenter) {
		presenter->Enable(TRUE);
	}

	m_unk0x100 = 1;
}

// FUNCTION: LEGO1 0x1005da70
// FUNCTION: BETA10 0x10037f6d
MxBool JukeBox::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	MxStillPresenter* presenter;

	if (p_param.m_enabledChild == 1) {
		switch (p_param.m_clickedObjectId) {
		case JukeboxwScript::c_Dback_Ctl:
			switch (m_state->m_music) {
			case JukeBoxState::e_pasquell:
				m_state->m_music = JukeBoxState::e_torpedos;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeBoxState::e_right:
				m_state->m_music = JukeBoxState::e_pasquell;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				presenter->Enable(FALSE);
				break;
			case JukeBoxState::e_decal:
				m_state->m_music = JukeBoxState::e_right;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeBoxState::e_wallis:
				m_state->m_music = JukeBoxState::e_decal;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeBoxState::e_nelson:
				m_state->m_music = JukeBoxState::e_wallis;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeBoxState::e_torpedos:
				m_state->m_music = JukeBoxState::e_nelson;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				presenter->Enable(TRUE);
				break;
			}
			break;
		case JukeboxwScript::c_Dfwd_Ctl:
			switch (m_state->m_music) {
			case JukeBoxState::e_pasquell:
				m_state->m_music = JukeBoxState::e_right;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeBoxState::e_right:
				m_state->m_music = JukeBoxState::e_decal;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeBoxState::e_decal:
				m_state->m_music = JukeBoxState::e_wallis;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeBoxState::e_wallis:
				m_state->m_music = JukeBoxState::e_nelson;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeBoxState::e_nelson:
				m_state->m_music = JukeBoxState::e_torpedos;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				presenter->Enable(FALSE);
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				presenter->Enable(TRUE);
				break;
			case JukeBoxState::e_torpedos:
				m_state->m_music = JukeBoxState::e_pasquell;
				presenter = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				presenter->Enable(FALSE);
				break;
			}
			break;
		case JukeboxwScript::c_Note_Ctl:
			Act1State* act1State = (Act1State*) GameState()->GetState("Act1State");
			act1State->m_state = Act1State::e_jukebox;
			m_destLocation = LegoGameState::Area::e_jukeboxExterior;
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
		Disable(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1005de70
MxBool JukeBox::Escape()
{
	m_destLocation = LegoGameState::e_infomain;
	return TRUE;
}
