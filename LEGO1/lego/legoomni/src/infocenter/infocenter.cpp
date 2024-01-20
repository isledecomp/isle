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
DECOMP_SIZE_ASSERT(InfocenterUnkDataEntry, 0x18)

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
	m_unk0x1cc = 0;
	m_unk0x11c = 0;
	m_unk0x104 = 0;
	m_currentInfomainScript = c_noInfomain;
	m_currentCutscene = e_noIntro;

	memset(&m_entries, 0, sizeof(m_entries));

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
		case c_notificationType17:
			result = HandleNotification17(p_param);
			break;
		case c_notificationTransitioned:
			StopBookAnimation();
			m_bookAnimationTimer = 0;

			if (m_infocenterState->GetUnknown0x74() == 0xc) {
				StartCredits();
				m_infocenterState->SetUnknown0x74(0xd);
			}
			else if (m_unk0x104 != 0) {
				BackgroundAudioManager()->RaiseVolume();
				GameState()->HandleAction(m_unk0x104);
				m_unk0x104 = 0;
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

			FUN_10070dc0(TRUE);
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
void Infocenter::VTable0x50()
{
	m_infoManDialogueTimer = 0;
	m_bookAnimationTimer = 0;
	m_unk0x1d4 = 0;
	m_unk0x1d6 = 0;

	MxStillPresenter* bg = (MxStillPresenter*) FindPresenter("MxStillPresenter", "Background_Bitmap");
	MxStillPresenter* bgRed = (MxStillPresenter*) FindPresenter("MxStillPresenter", "BackgroundRed_Bitmap");

	switch (GameState()->GetUnknown10()) {
	case 0:
		// bg->Enable(1); // TODO: Uncomment once LegoWorld::FindPresenter and LegoWorld::VTable0x58 are implemented.
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

// STUB: LEGO1 0x1006f9a0
void Infocenter::InitializeBitmaps()
{
	// TODO: Infocenter class size is wrong
}

// STUB: LEGO1 0x1006fd00
MxU8 Infocenter::HandleMouseMove(MxS32 p_x, MxS32 p_y)
{
	return 1;
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
	return 1;
}

// STUB: LEGO1 0x10070370
MxU8 Infocenter::HandleNotification17(MxParam&)
{
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

// STUB: LEGO1 0x10070dc0
void Infocenter::FUN_10070dc0(MxBool)
{
}

// STUB: LEGO1 0x10070e90
void Infocenter::FUN_10070e90()
{
}

// STUB: LEGO1 0x10070f60
MxBool Infocenter::VTable0x64()
{
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
