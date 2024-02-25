#include "jukebox.h"

#include "act1state.h"
#include "jukeboxstate.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"
#include "mxomni.h"
#include "mxstillpresenter.h"
#include "mxticklemanager.h"
#include "mxtransitionmanager.h"
#include "mxvideopresenter.h"

DECOMP_SIZE_ASSERT(JukeBox, 0x104)

// FUNCTION: LEGO1 0x1005d660
JukeBox::JukeBox()
{
	m_unk0x100 = 0;
	m_jukeBoxState = NULL;
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

	LegoGameState* gameState = GameState();
	JukeBoxState* jukeBoxState = (JukeBoxState*) gameState->GetState("JukeBoxState");
	if (!jukeBoxState) {
		jukeBoxState = (JukeBoxState*) gameState->CreateState("JukeBoxState");
		jukeBoxState->SetState(0);
	}

	m_jukeBoxState = jukeBoxState;
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
			GameState()->SwitchArea(m_transitionDestination);
			result = 1;
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1005d9f0
void JukeBox::ReadyWorld()
{
	MxStillPresenter* bg;
	char* objectName;

	switch (m_jukeBoxState->GetState()) {
	case 1:
		objectName = "Right_Bitmap";
		break;
	case 2:
		objectName = "Decal_Bitmap";
		break;
	case 3:
		objectName = "Wallis_Bitmap";
		break;
	case 4:
		objectName = "Nelson_Bitmap";
		break;
	case 5:
		objectName = "Torpedos_Bitmap";
		break;
	default:
		goto done;
	}
	bg = (MxStillPresenter*) Find("MxStillPresenter", objectName);
done:
	if (bg) {
		bg->Enable(TRUE);
	}
	m_unk0x100 = 1;
}

// FUNCTION: LEGO1 0x1005da70
MxBool JukeBox::HandleClick(LegoControlManagerEvent& p_param)
{
	MxStillPresenter* bg;
	if (p_param.GetUnknown0x28() == 1) {
		switch (p_param.GetClickedObjectId()) {
		case c_dBackCtl:
			switch (m_jukeBoxState->GetState()) {
			case JukeBoxScript::e_mamaPapaBrickolini:
				m_jukeBoxState->SetState(JukeBoxScript::e_residentialArea);
				bg = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				bg->Enable(TRUE);
				break;
			case JukeBoxScript::e_jailUnused:
				m_jukeBoxState->SetState(JukeBoxScript::e_mamaPapaBrickolini);
				bg = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				bg->Enable(FALSE);
				break;
			case JukeBoxScript::e_act2Cave:
				m_jukeBoxState->SetState(JukeBoxScript::e_jailUnused);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				bg->Enable(FALSE);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				bg->Enable(TRUE);
				break;
			case JukeBoxScript::e_bricksterChase:
				m_jukeBoxState->SetState(JukeBoxScript::e_act2Cave);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				bg->Enable(FALSE);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				bg->Enable(TRUE);
				break;
			case JukeBoxScript::e_brickHunt:
				m_jukeBoxState->SetState(JukeBoxScript::e_bricksterChase);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				bg->Enable(FALSE);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				bg->Enable(TRUE);
				break;
			case JukeBoxScript::e_residentialArea:
				m_jukeBoxState->SetState(JukeBoxScript::e_brickHunt);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				bg->Enable(FALSE);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				bg->Enable(TRUE);
				break;
			}
			return TRUE;
			break;
		case JukeBoxWorldScript::c_dFwdCtl:
			switch (m_jukeBoxState->GetState()) {
			case JukeBoxScript::e_mamaPapaBrickolini:
				m_jukeBoxState->SetState(JukeBoxScript::e_jailUnused);
				bg = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				bg->Enable(TRUE);
				break;
			case JukeBoxScript::e_jailUnused:
				m_jukeBoxState->SetState(JukeBoxScript::e_act2Cave);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Right_Bitmap");
				bg->Enable(FALSE);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				bg->Enable(TRUE);
				break;
			case JukeBoxScript::e_act2Cave:
				m_jukeBoxState->SetState(JukeBoxScript::e_bricksterChase);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Decal_Bitmap");
				bg->Enable(FALSE);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				bg->Enable(TRUE);
				break;
			case JukeBoxScript::e_bricksterChase:
				m_jukeBoxState->SetState(JukeBoxScript::e_brickHunt);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Wallis_Bitmap");
				bg->Enable(FALSE);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				bg->Enable(TRUE);
				break;
			case JukeBoxScript::e_brickHunt:
				m_jukeBoxState->SetState(JukeBoxScript::e_residentialArea);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Nelson_Bitmap");
				bg->Enable(FALSE);

				bg = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				bg->Enable(TRUE);
				break;
			case JukeBoxScript::e_residentialArea:
				m_jukeBoxState->SetState(JukeBoxScript::e_mamaPapaBrickolini);
				bg = (MxStillPresenter*) Find("MxStillPresenter", "Torpedos_Bitmap");
				bg->Enable(FALSE);
				break;
			}
			break;
		case JukeBoxWorldScript::c_noteCtl:
			LegoGameState* gameState = GameState();
			Act1State* act1State = (Act1State*) gameState->GetState("Act1State");
			act1State->SetUnknown18(11);
			m_transitionDestination = LegoGameState::Area::e_unk54;
			TransitionManager()->StartTransition(MxTransitionManager::e_pixelation, 50, 0, FALSE);
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
		FUN_10015820(FALSE, 7);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1005de70
MxBool JukeBox::VTable0x64()
{
	m_transitionDestination = LegoGameState::e_infomain;
	return TRUE;
}
