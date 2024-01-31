#include "infocenter.h"

#include "infocenterstate.h"
#include "jukebox.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "legoutil.h"
#include "legovideomanager.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxnotificationmanager.h"
#include "mxstillpresenter.h"
#include "mxticklemanager.h"
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(Infocenter, 0x1d8)
DECOMP_SIZE_ASSERT(InfocenterMapEntry, 0x18)

// GLOBAL: LEGO1 0x100f76a0
const char* g_object2x4red = "2x4red";

// GLOBAL: LEGO1 0x100f76a4
const char* g_object2x4grn = "2x4grn";

// FUNCTION: LEGO1 0x1006ea20
Infocenter::Infocenter()
{
	m_unk0xfc = 0;
	m_unk0x11c = 0;
	m_infocenterState = NULL;
	m_frameHotBitmap = 0;
	m_unk0x11c = 0;
	m_transitionDestination = 0;
	m_currentInfomainScript = c_noInfomain;
	m_currentCutscene = e_noIntro;

	memset(&m_mapAreas, 0, sizeof(m_mapAreas));

	m_unk0x1c8 = -1;
	SetAppCursor(1);
	NotificationManager()->Register(this);

	m_infoManDialogueTimer = 0;
	m_bookAnimationTimer = 0;
	m_unk0x1d4 = 0;
	m_unk0x1d6 = 0;
}

// FUNCTION: LEGO1 0x1006ec90
Infocenter::~Infocenter()
{
	BackgroundAudioManager()->Stop();

	MxS16 i = 0;
	do {
		if (m_infocenterState->GetInfocenterBufferElement(i) != NULL) {
			m_infocenterState->GetInfocenterBufferElement(i)->Enable(FALSE);
		}
		i++;
	} while (i < m_infocenterState->GetInfocenterBufferSize());

	ControlManager()->Unregister(this);

	InputManager()->UnRegister(this);
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	NotificationManager()->Unregister(this);

	TickleManager()->UnregisterClient(this);
}

// STUB: LEGO1 0x1006ed90
MxResult Infocenter::Create(MxDSAction& p_dsAction)
{
	if (LegoWorld::Create(p_dsAction) == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	LegoGameState* gs = GameState();
	m_infocenterState = (InfocenterState*) gs->GetState("InfocenterState");
	if (!m_infocenterState) {
		m_infocenterState = (InfocenterState*) gs->CreateState("InfocenterState");
		m_infocenterState->SetUnknown0x74(3);
	}
	else {
		// TODO
	}

	// TODO
	InputManager()->Register(this);
	SetIsWorldActive(FALSE);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1006ef10
MxLong Infocenter::Notify(MxParam& p_param)
{
	MxLong result = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetNotification()) {
		case c_notificationType0:
			result = HandleNotification0(p_param);
			break;
		case c_notificationEndAction:
			result = HandleEndAction(p_param);
			break;
		case c_notificationKeyPress:
			result = HandleKeyPress(((LegoEventNotificationParam&) p_param).GetKey());
			break;
		case c_notificationButtonUp:
			result = HandleButtonUp(
				((LegoEventNotificationParam&) p_param).GetX(),
				((LegoEventNotificationParam&) p_param).GetY()
			);
			break;
		case c_notificationMouseMove:
			result = HandleMouseMove(
				((LegoEventNotificationParam&) p_param).GetX(),
				((LegoEventNotificationParam&) p_param).GetY()
			);
			break;
		case c_notificationClick:
			result = HandleClick((LegoControlManagerEvent&) p_param);
			break;
		case c_notificationTransitioned:
			StopBookAnimation();
			m_bookAnimationTimer = 0;

			if (m_infocenterState->GetUnknown0x74() == 0x0c) {
				StartCredits();
				m_infocenterState->SetUnknown0x74(0xd);
			}
			else if (m_transitionDestination != 0) {
				BackgroundAudioManager()->RaiseVolume();
				GameState()->SwitchArea(m_transitionDestination);
				m_transitionDestination = 0;
			}
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1006f080
MxLong Infocenter::HandleEndAction(MxParam& p_param)
{
	MxDSAction* action = ((MxEndActionNotificationParam&) p_param).GetAction();
	if (action->GetAtomId() == *g_creditsScript && action->GetObjectId() == 499) {
		Lego()->CloseMainWindow();
		return 1;
	}

	if (action->GetAtomId() == m_atom &&
		(action->GetObjectId() == 40 || action->GetObjectId() == 41 || action->GetObjectId() == 42 ||
		 action->GetObjectId() == 43 || action->GetObjectId() == 44)) {
		if (m_unk0x1d4) {
			m_unk0x1d4--;
		}

		if (!m_unk0x1d4) {
			PlayMusic(JukeBox::e_informationCenter);
			GameState()->FUN_10039780(m_unk0xfc);

			switch (m_unk0xfc) {
			case 1:
				PlayAction(c_pepperCharacterSelect);
				break;
			case 2:
				PlayAction(c_mamaCharacterSelect);
				break;
			case 3:
				PlayAction(c_papaCharacterSelect);
				break;
			case 4:
				PlayAction(c_nickCharacterSelect);
				break;
			case 5:
				PlayAction(c_lauraCharacterSelect);
				break;
			default:
				break;
			}

			UpdateFrameHot(TRUE);
		}
	}

	MxLong result = m_radio.Notify(p_param);

	if (result || (action->GetAtomId() != m_atom && action->GetAtomId() != *g_introScript))
		return result;

	if (action->GetObjectId() == c_returnBackGuidanceDialogue2) {
		ControlManager()->FUN_100293c0(0x10, action->GetAtomId().GetInternal(), 0);
		m_unk0x1d6 = 0;
	}

	switch (m_infocenterState->GetUnknown0x74()) {
	case 0:
		switch (m_currentCutscene) {
		case e_legoMovie:
			PlayCutscene(e_mindscapeMovie, FALSE);
			return 1;
		case e_mindscapeMovie:
			PlayCutscene(e_introMovie, TRUE);
			return 1;
		case e_badEndMovie:
			StopCutscene();
			m_infocenterState->SetUnknown0x74(11);
			PlayAction(c_badEndingDialogue);
			m_currentCutscene = e_noIntro;
			return 1;
		case e_goodEndMovie:
			StopCutscene();
			m_infocenterState->SetUnknown0x74(11);
			PlayAction(c_goodEndingDialogue);
			m_currentCutscene = e_noIntro;
			return 1;
		}

		// default / 2nd case probably?
		StopCutscene();
		m_infocenterState->SetUnknown0x74(11);
		PlayAction(c_welcomeDialogue);
		m_currentCutscene = e_noIntro;

		if (m_infocenterState->GetInfocenterBufferElement(0) == 0) {
			m_bookAnimationTimer = 1;
			return 1;
		}
		break;
	case 1:
		m_infocenterState->SetUnknown0x74(11);

		switch (m_currentCutscene) {
		case e_badEndMovie:
			PlayAction(c_badEndingDialogue);
			break;
		case e_goodEndMovie:
			PlayAction(c_goodEndingDialogue);
			break;
		default:
			PlayAction(c_welcomeDialogue);
		}

		m_currentCutscene = e_noIntro;
		return 1;
	case 2:
		FUN_10015860(g_object2x4red, 0);
		FUN_10015860(g_object2x4grn, 0);
		BackgroundAudioManager()->RaiseVolume();
		return 1;
	case 4:
		if (action->GetObjectId() == 70 || action->GetObjectId() == 71) {
			TransitionManager()->StartTransition(MxTransitionManager::e_pixelation, 50, FALSE, FALSE);
			m_infocenterState->SetUnknown0x74(14);
			return 1;
		}
		break;
	case 5:
		if (action->GetObjectId() == m_currentInfomainScript) {
			if (GameState()->GetUnknown10() != 2 && m_unk0xfc != 0) {
				GameState()->FUN_10039780(m_unk0xfc);
			}
			TransitionManager()->StartTransition(MxTransitionManager::e_pixelation, 50, FALSE, FALSE);
			m_infocenterState->SetUnknown0x74(14);
			return 1;
		}
		break;
	case 11:
		if (m_infocenterState->GetInfocenterBufferElement(0) == 0 && m_currentInfomainScript != 40 &&
			m_currentInfomainScript != 41 && m_currentInfomainScript != 42 && m_currentInfomainScript != 43 &&
			m_currentInfomainScript != 44) {
			m_infoManDialogueTimer = 1;
			PlayMusic(JukeBox::e_informationCenter);
		}

		m_infocenterState->SetUnknown0x74(2);
		FUN_10015860("infoman", 1);
		return 1;
	case 12:
		if (action->GetObjectId() == m_currentInfomainScript) {
			TransitionManager()->StartTransition(MxTransitionManager::e_pixelation, 50, FALSE, FALSE);
		}
	}

	result = 1;

	return result;
}

// STUB: LEGO1 0x1006f4e0
void Infocenter::ReadyWorld()
{
	m_infoManDialogueTimer = 0;
	m_bookAnimationTimer = 0;
	m_unk0x1d4 = 0;
	m_unk0x1d6 = 0;

	MxStillPresenter* bg = (MxStillPresenter*) Find("MxStillPresenter", "Background_Bitmap");
	MxStillPresenter* bgRed = (MxStillPresenter*) Find("MxStillPresenter", "BackgroundRed_Bitmap");

	switch (GameState()->GetUnknown10()) {
	case 0:
		bg->Enable(1);
		InitializeBitmaps();
		switch (m_infocenterState->GetUnknown0x74()) {
		case 3:
			PlayCutscene(e_legoMovie, TRUE);
			m_infocenterState->SetUnknown0x74(0);
			return;
		case 4:
			m_infocenterState->SetUnknown0x74(2);
			if (m_infocenterState->GetInfocenterBufferElement(0) == 0) {
				m_bookAnimationTimer = 1;
			}

			PlayAction(c_letsGetStartedDialogue);
			PlayMusic(JukeBox::e_informationCenter);
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			return;
		default:
			PlayMusic(JukeBox::e_informationCenter);
			// TODO
			break;
		case 8:
			PlayMusic(JukeBox::e_informationCenter);
			PlayAction(c_exitConfirmationDialogue);
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			return;
		case 0xf:
			if (m_infocenterState->GetInfocenterBufferElement(0) == 0) {
				m_bookAnimationTimer = 1;
			}

			PlayAction(c_clickOnInfomanDialogue);
			PlayMusic(JukeBox::e_informationCenter);
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			return;
		}
		break;
	case 1:
		// TODO
		break;
	case 2:
		// TODO
		break;
	default:
		m_infocenterState->SetUnknown0x74(11);
		FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
		return;
	}
}

// FUNCTION: LEGO1 0x1006f9a0
void Infocenter::InitializeBitmaps()
{
	m_radio.Initialize(TRUE);

	((MxPresenter*) Find(m_atom, c_leftArrowCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_rightArrowCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_infoCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_boatCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_raceCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_pizzaCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_gasCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_medCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_copCtl))->Enable(TRUE);

	((MxPresenter*) Find(m_atom, c_mamaCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_papaCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_pepperCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_nickCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_lauraCtl))->Enable(TRUE);
	((MxPresenter*) Find(m_atom, c_radioCtl))->Enable(TRUE);

	m_mapAreas[0].m_presenter = (MxStillPresenter*) Find("MxStillPresenter", "Info_A_Bitmap");
	m_mapAreas[0].m_unk0x08 = 391;
	m_mapAreas[0].m_unk0x0c = 182;
	m_mapAreas[0].m_unk0x10 = 427;
	m_mapAreas[0].m_unk0x14 = 230;
	m_mapAreas[0].m_unk0x04 = 3;

	m_mapAreas[1].m_presenter = (MxStillPresenter*) Find("MxStillPresenter", "Boat_A_Bitmap");
	m_mapAreas[1].m_unk0x08 = 304;
	m_mapAreas[1].m_unk0x0c = 225;
	m_mapAreas[1].m_unk0x10 = 350;
	m_mapAreas[1].m_unk0x14 = 268;
	m_mapAreas[1].m_unk0x04 = 10;

	m_mapAreas[2].m_presenter = (MxStillPresenter*) Find("MxStillPresenter", "Race_A_Bitmap");
	m_mapAreas[2].m_unk0x08 = 301;
	m_mapAreas[2].m_unk0x0c = 133;
	m_mapAreas[2].m_unk0x10 = 347;
	m_mapAreas[2].m_unk0x14 = 181;
	m_mapAreas[2].m_unk0x04 = 11;

	m_mapAreas[3].m_presenter = (MxStillPresenter*) Find("MxStillPresenter", "Pizza_A_Bitmap");
	m_mapAreas[3].m_unk0x08 = 289;
	m_mapAreas[3].m_unk0x0c = 182;
	m_mapAreas[3].m_unk0x10 = 335;
	m_mapAreas[3].m_unk0x14 = 225;
	m_mapAreas[3].m_unk0x04 = 12;

	m_mapAreas[4].m_presenter = (MxStillPresenter*) Find("MxStillPresenter", "Gas_A_Bitmap");
	m_mapAreas[4].m_unk0x10 = 391;
	m_mapAreas[4].m_unk0x08 = 350;
	m_mapAreas[4].m_unk0x0c = 161;
	m_mapAreas[4].m_unk0x14 = 209;
	m_mapAreas[4].m_unk0x04 = 13;

	m_mapAreas[5].m_presenter = (MxStillPresenter*) Find("MxStillPresenter", "Med_A_Bitmap");
	m_mapAreas[5].m_unk0x08 = 392;
	m_mapAreas[5].m_unk0x0c = 130;
	m_mapAreas[5].m_unk0x10 = 438;
	m_mapAreas[5].m_unk0x14 = 176;
	m_mapAreas[5].m_unk0x04 = 14;

	m_mapAreas[6].m_presenter = (MxStillPresenter*) Find("MxStillPresenter", "Cop_A_Bitmap");
	m_mapAreas[6].m_unk0x08 = 396;
	m_mapAreas[6].m_unk0x0c = 229;
	m_mapAreas[6].m_unk0x10 = 442;
	m_mapAreas[6].m_unk0x14 = 272;
	m_mapAreas[6].m_unk0x04 = 15;

	m_frameHotBitmap = (MxStillPresenter*) Find("MxStillPresenter", "FrameHot_Bitmap");

	UpdateFrameHot(TRUE);
}

// FUNCTION: LEGO1 0x1006fd00
MxU8 Infocenter::HandleMouseMove(MxS32 p_x, MxS32 p_y)
{
	if (m_unk0x11c) {
		if (!m_unk0x11c->IsEnabled()) {
			MxS32 oldDisplayZ = m_unk0x11c->GetDisplayZ();

			m_unk0x11c->SetDisplayZ(1000);
			VideoManager()->SortPresenterList();
			m_unk0x11c->Enable(TRUE);
			m_unk0x11c->VTable0x88(p_x, p_y);

			m_unk0x11c->SetDisplayZ(oldDisplayZ);
		}
		else {
			m_unk0x11c->VTable0x88(p_x, p_y);
		}

		FUN_10070d10(p_x, p_y);
		return 1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1006fda0
MxLong Infocenter::HandleKeyPress(MxS8 p_key)
{
	MxLong result = 0;

	if (p_key == ' ' && m_worldStarted) {
		switch (m_infocenterState->GetUnknown0x74()) {
		case 0:
			StopCutscene();
			m_infocenterState->SetUnknown0x74(1);

			if (m_infocenterState->GetInfocenterBufferElement(0) == 0) {
				m_bookAnimationTimer = 1;
				return 1;
			}
			break;
		case 1:
		case 4:
			break;
		default: {
			InfomainScript script = m_currentInfomainScript;
			StopCurrentAction();

			switch (m_infocenterState->GetUnknown0x74()) {
			case 5:
			case 12:
				m_currentInfomainScript = script;
				return 1;
			default:
				m_infocenterState->SetUnknown0x74(2);
				return 1;
			case 8:
			case 11:
				break;
			}
		}
		case 13:
			StopCredits();
			break;
		}

		result = 1;
	}

	return result;
}

// STUB: LEGO1 0x1006feb0
MxU8 Infocenter::HandleButtonUp(MxS32 p_x, MxS32 p_y)
{
	return FALSE;
}

// FUNCTION: LEGO1 0x10070370
MxU8 Infocenter::HandleClick(LegoControlManagerEvent& p_param)
{
	if (p_param.GetUnknown0x28() == 1) {
		m_infoManDialogueTimer = 0;

		InfomainScript actionToPlay = c_noInfomain;
		StopCurrentAction();
		InfomainScript characterBitmap = c_noInfomain;

		GameState();

		switch (p_param.GetClickedObjectId()) {
		case c_leftArrowCtl:
			m_infocenterState->SetUnknown0x74(14);
			StopCurrentAction();

			if (GameState()->GetUnknown10() == 0) {
				m_radio.Stop();
				TransitionManager()->StartTransition(MxTransitionManager::e_pixelation, 50, FALSE, FALSE);
				m_transitionDestination = 5;
			}
			else {
				MxU32 objectId = m_infocenterState->GetUnknown0x68().FUN_10014d00();
				PlayAction((InfomainScript) objectId);
			}

			break;
		case c_rightArrowCtl:
			m_infocenterState->SetUnknown0x74(14);
			StopCurrentAction();

			if (GameState()->GetUnknown10() == 0) {
				m_radio.Stop();
				TransitionManager()->StartTransition(MxTransitionManager::e_pixelation, 50, FALSE, FALSE);
				m_transitionDestination = 13;
			}
			else {
				MxU32 objectId = m_infocenterState->GetUnknown0x68().FUN_10014d00();
				PlayAction((InfomainScript) objectId);
			}

			break;
		case c_infoCtl:
			m_radio.Stop();
			break;
		case c_doorCtl:
			if (m_infocenterState->GetUnknown0x74() != 8) {
				actionToPlay = c_exitConfirmationDialogue;
				m_radio.Stop();
				m_infocenterState->SetUnknown0x74(8);
			}

			break;
		case c_boatCtl:
			actionToPlay = c_boatCtlDescription;
			m_radio.Stop();
			break;
		case c_raceCtl:
			actionToPlay = c_raceCtlDescription;
			m_radio.Stop();
			break;
		case c_pizzaCtl:
			actionToPlay = c_pizzaCtlDescription;
			m_radio.Stop();
			break;
		case c_gasCtl:
			actionToPlay = c_gasCtlDescription;
			m_radio.Stop();
			break;
		case c_medCtl:
			actionToPlay = c_medCtlDescription;
			m_radio.Stop();
			break;
		case c_copCtlDescription:
			actionToPlay = c_copCtlDescription;
			m_radio.Stop();
			break;
		case c_bigInfoCtl:
			// TODO
			break;
		case c_bookCtl:
			m_transitionDestination = 12;
			m_infocenterState->SetUnknown0x74(4);
			actionToPlay = GameState()->GetUnknown10() ? c_goToRegBookRed : c_goToRegBook;
			m_radio.Stop();
			GameState()->SetCurrentArea(GameState()->GetPreviousArea());
			InputManager()->DisableInputProcessing();
			break;
		case c_mamaCtl:
			characterBitmap = c_mamaSelected;
			UpdateFrameHot(FALSE);
			break;
		case c_papaCtl:
			characterBitmap = c_papaSelected;
			UpdateFrameHot(FALSE);
			break;
		case c_pepperCtl:
			characterBitmap = c_pepperSelected;
			UpdateFrameHot(FALSE);
			break;
		case c_nickCtl:
			characterBitmap = c_nickSelected;
			UpdateFrameHot(FALSE);
			break;
		case c_lauraCtl:
			characterBitmap = c_lauraCtl;
			UpdateFrameHot(FALSE);
			break;
		}

		if (actionToPlay != c_noInfomain) {
			PlayAction(actionToPlay);
		}

		if (characterBitmap != c_noInfomain) {
			m_unk0x11c = (MxStillPresenter*) Find(m_atom, characterBitmap);
		}
	}

	return 1;
}

// STUB: LEGO1 0x10070870
MxLong Infocenter::HandleNotification0(MxParam&)
{
	return 1;
}

// FUNCTION: LEGO1 0x10070aa0
void Infocenter::VTable0x68(MxBool p_add)
{
	LegoWorld::VTable0x68(p_add);

	if (p_add) {
		InputManager()->SetWorld(this);
		SetIsWorldActive(FALSE);
	}
	else {
		if (InputManager()->GetWorld() == this) {
			InputManager()->ClearWorld();
		}
	}
}

// FUNCTION: LEGO1 0x10070af0
MxResult Infocenter::Tickle()
{
	if (m_worldStarted == FALSE) {
		LegoWorld::Tickle();
		return SUCCESS;
	}

	if (m_infoManDialogueTimer != 0 && (m_infoManDialogueTimer += 100) > 25000) {
		PlayAction(c_clickOnInfomanDialogue);
		m_infoManDialogueTimer = 0;
	}

	if (m_bookAnimationTimer != 0 && (m_bookAnimationTimer += 100) > 3000) {
		PlayBookAnimation();
		m_bookAnimationTimer = 1;
	}

	if (m_unk0x1d6 != 0) {
		m_unk0x1d6 += 100;

		if (m_unk0x1d6 > 3400 && m_unk0x1d6 < 3650) {
			ControlManager()->FUN_100293c0(0x10, m_atom.GetInternal(), 1);
		}
		else if (m_unk0x1d6 > 3650 && m_unk0x1d6 < 3900) {
			ControlManager()->FUN_100293c0(0x10, m_atom.GetInternal(), 0);
		}
		else if (m_unk0x1d6 > 3900 && m_unk0x1d6 < 4150) {
			ControlManager()->FUN_100293c0(0x10, m_atom.GetInternal(), 1);
		}
		else if (m_unk0x1d6 > 4400) {
			ControlManager()->FUN_100293c0(0x10, m_atom.GetInternal(), 0);
			m_unk0x1d6 = 0;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10070c20
void Infocenter::PlayCutscene(Cutscene p_entityId, MxBool p_scale)
{
	m_currentCutscene = p_entityId;

	VideoManager()->EnableFullScreenMovie(TRUE, p_scale);
	InputManager()->SetUnknown336(TRUE);
	InputManager()->SetUnknown335(TRUE);
	SetAppCursor(0xb); // Hide cursor
	VideoManager()->GetDisplaySurface()->ClearScreen();

	if (m_currentCutscene != e_noIntro) {
		// check if the cutscene is not an ending
		if (m_currentCutscene >= e_badEndMovie && m_currentCutscene <= e_goodEndMovie) {
			FUN_10070e90();
		}
		InvokeAction(Extra::ActionType::e_opendisk, *g_introScript, m_currentCutscene, NULL);
	}
}

// FUNCTION: LEGO1 0x10070cb0
void Infocenter::StopCutscene()
{
	if (m_currentCutscene != e_noIntro) {
		InvokeAction(Extra::ActionType::e_close, *g_introScript, m_currentCutscene, NULL);
	}

	VideoManager()->EnableFullScreenMovie(FALSE);
	InputManager()->SetUnknown335(FALSE);
	SetAppCursor(0); // Restore cursor to arrow
	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x10070d00
MxBool Infocenter::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x10070d10
void Infocenter::FUN_10070d10(MxS32 p_x, MxS32 p_y)
{
	MxS16 i;
	for (i = 0; i < sizeof(m_mapAreas) / sizeof(InfocenterMapEntry); i++) {
		if (m_mapAreas[i].m_unk0x08 <= p_x && p_x <= m_mapAreas[i].m_unk0x10 && m_mapAreas[i].m_unk0x0c <= p_y &&
			p_y <= m_mapAreas[i].m_unk0x14) {
			break;
		}
	}

	if (i == 7) {
		i = -1;
	}

	if (i != m_unk0x1c8) {
		if (m_unk0x1c8 != -1) {
			m_mapAreas[i].m_presenter->Enable(FALSE);
		}

		m_unk0x1c8 = i;
		if (i != -1) {
			m_mapAreas[i].m_presenter->Enable(TRUE);
		}
	}
}

// FUNCTION: LEGO1 0x10070dc0
void Infocenter::UpdateFrameHot(MxBool p_display)
{
	if (p_display) {
		MxU32 x;
		switch (GameState()->GetUnknownC()) {
		case 1:
			x = 302;
			break;
		case 2:
			x = 204;
			break;
		case 3:
			x = 253;
			break;
		case 4:
			x = 353;
			break;
		case 5:
			x = 399;
			break;
		default:
			return;
		}

		MxS32 oldZ = m_frameHotBitmap->GetDisplayZ();

		m_frameHotBitmap->SetDisplayZ(1000);
		VideoManager()->SortPresenterList();
		m_frameHotBitmap->Enable(TRUE);
		m_frameHotBitmap->VTable0x88(x, 81);

		m_frameHotBitmap->SetDisplayZ(oldZ);
	}
	else {
		if (m_frameHotBitmap) {
			m_frameHotBitmap->Enable(FALSE);
		}
	}
}

// STUB: LEGO1 0x10070e90
void Infocenter::FUN_10070e90()
{
}

// FUNCTION: LEGO1 0x10070f60
MxBool Infocenter::VTable0x64()
{
	if (m_infocenterState != NULL) {
		MxU32 val = m_infocenterState->GetUnknown0x74();
		if (val == 0) {
			StopCutscene();
			m_infocenterState->SetUnknown0x74(1);
		}
		else if (val == 13) {
			StopCredits();
		}
		else if (val != 8) {
#ifdef COMPAT_MODE
			{
				MxNotificationParam param(c_notificationType0, NULL);
				Notify(param);
			}
#else
			Notify(MxNotificationParam(c_notificationType0, NULL));
#endif
		}
	}

	return FALSE;
}

// STUB: LEGO1 0x10071030
void Infocenter::StartCredits()
{
	// TODO
}

// FUNCTION: LEGO1 0x10071250
void Infocenter::StopCredits()
{
	MxDSAction action;
	action.SetObjectId(499);
	action.SetAtomId(*g_creditsScript);
	action.SetUnknown24(-2);
	DeleteObject(action);
}

// FUNCTION: LEGO1 0x10071300
void Infocenter::PlayAction(InfomainScript p_objectId)
{
	MxDSAction action;
	action.SetObjectId(p_objectId);
	action.SetAtomId(*g_infomainScript);
	StopCurrentAction();

	m_currentInfomainScript = p_objectId;
	BackgroundAudioManager()->LowerVolume();
	Start(&action);
}

// FUNCTION: LEGO1 0x100713d0
void Infocenter::StopCurrentAction()
{
	if (m_currentInfomainScript != c_noInfomain) {
		MxDSAction action;
		action.SetObjectId(m_currentInfomainScript);
		action.SetAtomId(*g_infomainScript);
		action.SetUnknown24(-2);
		DeleteObject(action);
		m_currentInfomainScript = c_noInfomain;
	}
}

// FUNCTION: LEGO1 0x100714a0
void Infocenter::PlayBookAnimation()
{
	MxDSAction action;
	action.SetObjectId(c_bookWig);
	action.SetAtomId(*g_sndAnimScript);
	Start(&action);
}

// FUNCTION: LEGO1 0x10071550
void Infocenter::StopBookAnimation()
{
	MxDSAction action;
	action.SetObjectId(c_bookWig);
	action.SetAtomId(*g_sndAnimScript);
	action.SetUnknown24(-2);
	DeleteObject(action);
}
