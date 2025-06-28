#include "infocenter.h"

#include "act3.h"
#include "credits_actions.h"
#include "helicopter.h"
#include "infomain_actions.h"
#include "jukebox.h"
#include "jukebox_actions.h"
#include "legoact2.h"
#include "legoanimationmanager.h"
#include "legobuildingmanager.h"
#include "legocharactermanager.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legomain.h"
#include "legoplantmanager.h"
#include "legoutils.h"
#include "legovideomanager.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxcontrolpresenter.h"
#include "mxdisplaysurface.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstillpresenter.h"
#include "mxticklemanager.h"
#include "mxtransitionmanager.h"
#include "mxutilities.h"
#include "scripts.h"
#include "sndanim_actions.h"
#include "viewmanager/viewmanager.h"

DECOMP_SIZE_ASSERT(Infocenter, 0x1d8)
DECOMP_SIZE_ASSERT(InfocenterMapEntry, 0x18)
DECOMP_SIZE_ASSERT(InfocenterState, 0x94)

// GLOBAL: LEGO1 0x100f76a0
const char* g_object2x4red = "2x4red";

// GLOBAL: LEGO1 0x100f76a4
const char* g_object2x4grn = "2x4grn";

// GLOBAL: LEGO1 0x100f76a8
InfomainScript::Script g_exitDialogueAct1[14] = {
	InfomainScript::c_iic019in_RunAnim,
	InfomainScript::c_iic020in_RunAnim,
	InfomainScript::c_iic021in_RunAnim,
	InfomainScript::c_iic022in_RunAnim,
	InfomainScript::c_iic023in_RunAnim,
	InfomainScript::c_iic024in_RunAnim,
	InfomainScript::c_iic025in_RunAnim,
	InfomainScript::c_iic026in_RunAnim,
	InfomainScript::c_iic027in_RunAnim,
	InfomainScript::c_iica28in_RunAnim,
	InfomainScript::c_iicb28in_RunAnim,
	InfomainScript::c_iicc28in_RunAnim,
	InfomainScript::c_iic029in_RunAnim,
	InfomainScript::c_iic032in_RunAnim
};

// GLOBAL: LEGO1 0x100f76e0
InfomainScript::Script g_exitDialogueAct23[6] = {
	InfomainScript::c_iic027in_RunAnim,
	InfomainScript::c_iic029in_RunAnim,
	InfomainScript::c_iic048in_RunAnim,
	InfomainScript::c_iic056in_RunAnim,
	InfomainScript::c_iicx23in_RunAnim
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f76f8
InfomainScript::Script g_returnDialogueAct1[6] = {
	InfomainScript::c_iicx26in_RunAnim,
	InfomainScript::c_iic033in_RunAnim,
	InfomainScript::c_iic034in_RunAnim,
	InfomainScript::c_iic035in_RunAnim,
	InfomainScript::c_iic036in_RunAnim
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7710
InfomainScript::Script g_returnDialogueAct2[4] = {
	InfomainScript::c_iic048in_RunAnim,
	InfomainScript::c_iic049in_RunAnim,
	InfomainScript::c_iic050in_RunAnim,
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7720
InfomainScript::Script g_returnDialogueAct3[4] = {
	InfomainScript::c_iic055in_RunAnim,
	InfomainScript::c_iic056in_RunAnim,
	InfomainScript::c_iic057in_RunAnim,
	InfomainScript::c_iic058in_RunAnim
};

// GLOBAL: LEGO1 0x100f7730
InfomainScript::Script g_leaveDialogueAct1[4] = {
	InfomainScript::c_iic039in_PlayWav,
	InfomainScript::c_iic040in_PlayWav,
	InfomainScript::c_iic041in_PlayWav,
	InfomainScript::c_iic042in_PlayWav
};

// GLOBAL: LEGO1 0x100f7740
InfomainScript::Script g_leaveDialogueAct2[4] = {
	InfomainScript::c_iic051in_PlayWav,
	InfomainScript::c_iic052in_PlayWav,
	InfomainScript::c_iic053in_PlayWav,
	InfomainScript::c_iic054in_PlayWav
};

// GLOBAL: LEGO1 0x100f7750
InfomainScript::Script g_leaveDialogueAct3[4] = {
	InfomainScript::c_iic059in_PlayWav,
	InfomainScript::c_iic060in_PlayWav,
	InfomainScript::c_iic061in_PlayWav,
	// Zero-terminated
};

// GLOBAL: LEGO1 0x100f7760
InfomainScript::Script g_bricksterDialogue[2] = {
	InfomainScript::c_sbleh2br_PlayWav,
	InfomainScript::c_snshahbr_PlayWav
};

// FUNCTION: LEGO1 0x1006ea20
Infocenter::Infocenter()
{
	m_selectedCharacter = e_noCharacter;
	m_dragPresenter = NULL;
	m_infocenterState = NULL;
	m_frame = NULL;
	m_destLocation = LegoGameState::e_undefined;
	m_currentInfomainScript = InfomainScript::c_noneInfomain;
	m_currentCutscene = e_noIntro;

	memset(&m_glowInfo, 0, sizeof(m_glowInfo));

	m_unk0x1c8 = -1;
	SetAppCursor(e_cursorBusy);
	NotificationManager()->Register(this);

	m_infoManDialogueTimer = 0;
	m_bookAnimationTimer = 0;
	m_unk0x1d4 = 0;
	m_unk0x1d6 = 0;
}

// FUNCTION: LEGO1 0x1006ec80
InfocenterMapEntry::InfocenterMapEntry()
{
}

// FUNCTION: LEGO1 0x1006ec90
Infocenter::~Infocenter()
{
	BackgroundAudioManager()->Stop();

	MxS16 i = 0;
	do {
		if (m_infocenterState->GetNameLetter(i) != NULL) {
			m_infocenterState->GetNameLetter(i)->Enable(FALSE);
		}
		i++;
	} while (i < m_infocenterState->GetMaxNameLength());

	ControlManager()->Unregister(this);

	InputManager()->UnRegister(this);
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	NotificationManager()->Unregister(this);

	TickleManager()->UnregisterClient(this);
}

// FUNCTION: LEGO1 0x1006ed90
MxResult Infocenter::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	m_infocenterState = (InfocenterState*) GameState()->GetState("InfocenterState");
	if (!m_infocenterState) {
		m_infocenterState = (InfocenterState*) GameState()->CreateState("InfocenterState");
		m_infocenterState->m_unk0x74 = 3;
	}
	else {
		if (m_infocenterState->m_unk0x74 != 8 && m_infocenterState->m_unk0x74 != 4 &&
			m_infocenterState->m_unk0x74 != 15) {
			m_infocenterState->m_unk0x74 = 2;
		}

		MxS16 count, i;
		for (count = 0; count < m_infocenterState->GetMaxNameLength(); count++) {
			if (m_infocenterState->GetNameLetter(count) == NULL) {
				break;
			}
		}

		for (i = 0; i < count; i++) {
			if (m_infocenterState->GetNameLetter(i)) {
				m_infocenterState->GetNameLetter(i)->Enable(TRUE);
				m_infocenterState->GetNameLetter(i)->SetTickleState(MxPresenter::e_repeating);
				m_infocenterState->GetNameLetter(i)->SetPosition(((7 - count) / 2 + i) * 29 + 223, 45);
			}
		}
	}

	GameState()->m_currentArea = LegoGameState::e_infomain;
	GameState()->StopArea(LegoGameState::e_previousArea);

	if (m_infocenterState->m_unk0x74 == 4) {
		LegoGameState* state = GameState();
		state->m_previousArea = GameState()->m_unk0x42c;
	}

	InputManager()->Register(this);
	SetIsWorldActive(FALSE);

	return result;
}

// FUNCTION: LEGO1 0x1006ef10
// FUNCTION: BETA10 0x1002eaca
MxLong Infocenter::Notify(MxParam& p_param)
{
	MxNotificationParam& param = (MxNotificationParam&) p_param;
	MxLong result = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (param.GetNotification()) {
		case c_notificationType0:
			result = HandleNotification0((MxNotificationParam&) p_param);
			break;
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
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
		case c_notificationControl:
			result = HandleControl((LegoControlManagerNotificationParam&) p_param);
			break;
		case c_notificationTransitioned:
			StopBookAnimation();
			m_bookAnimationTimer = 0;

			if (m_infocenterState->m_unk0x74 == 0x0c) {
				StartCredits();
				m_infocenterState->m_unk0x74 = 0xd;
			}
			else if (m_destLocation != 0) {
				BackgroundAudioManager()->RaiseVolume();
				GameState()->SwitchArea(m_destLocation);
				m_destLocation = LegoGameState::e_undefined;
			}
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1006f080
MxLong Infocenter::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	MxDSAction* action = p_param.GetAction();
	if (action->GetAtomId() == *g_creditsScript && action->GetObjectId() == CreditsScript::c_LegoCredits) {
		Lego()->CloseMainWindow();
		return 1;
	}

	if (action->GetAtomId() == m_atomId && (action->GetObjectId() == InfomainScript::c_Mama_All_Movie ||
											action->GetObjectId() == InfomainScript::c_Papa_All_Movie ||
											action->GetObjectId() == InfomainScript::c_Pepper_All_Movie ||
											action->GetObjectId() == InfomainScript::c_Nick_All_Movie ||
											action->GetObjectId() == InfomainScript::c_Laura_All_Movie)) {
		if (m_unk0x1d4) {
			m_unk0x1d4--;
		}

		if (!m_unk0x1d4) {
			PlayMusic(JukeboxScript::c_InformationCenter_Music);
			GameState()->SetActor(m_selectedCharacter);

			switch (m_selectedCharacter) {
			case e_pepper:
				PlayAction(InfomainScript::c_avo901in_RunAnim);
				break;
			case e_mama:
				PlayAction(InfomainScript::c_avo902in_RunAnim);
				break;
			case e_papa:
				PlayAction(InfomainScript::c_avo903in_RunAnim);
				break;
			case e_nick:
				PlayAction(InfomainScript::c_avo904in_RunAnim);
				break;
			case e_laura:
				PlayAction(InfomainScript::c_avo905in_RunAnim);
				break;
			default:
				break;
			}

			UpdateFrameHot(TRUE);
		}
	}

	MxLong result = m_radio.Notify(p_param);

	if (result || (action->GetAtomId() != m_atomId && action->GetAtomId() != *g_introScript)) {
		return result;
	}

	if (action->GetObjectId() == InfomainScript::c_iicx26in_RunAnim) {
		ControlManager()->FUN_100293c0(InfomainScript::c_BigInfo_Ctl, action->GetAtomId().GetInternal(), 0);
		m_unk0x1d6 = 0;
	}

	switch (m_infocenterState->m_unk0x74) {
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
			m_infocenterState->m_unk0x74 = 11;
			PlayAction(InfomainScript::c_tic092in_RunAnim);
			m_currentCutscene = e_noIntro;
			return 1;
		case e_goodEndMovie:
			StopCutscene();
			m_infocenterState->m_unk0x74 = 11;
			PlayAction(InfomainScript::c_tic089in_RunAnim);
			m_currentCutscene = e_noIntro;
			return 1;
		}

		// default / 2nd case probably?
		StopCutscene();
		m_infocenterState->m_unk0x74 = 11;
		PlayAction(InfomainScript::c_iic001in_RunAnim);
		m_currentCutscene = e_noIntro;

		if (!m_infocenterState->HasRegistered()) {
			m_bookAnimationTimer = 1;
			return 1;
		}
		break;
	case 1:
		m_infocenterState->m_unk0x74 = 11;

		switch (m_currentCutscene) {
		case e_badEndMovie:
			PlayAction(InfomainScript::c_tic092in_RunAnim);
			break;
		case e_goodEndMovie:
			PlayAction(InfomainScript::c_tic089in_RunAnim);
			break;
		default:
			PlayAction(InfomainScript::c_iic001in_RunAnim);
		}

		m_currentCutscene = e_noIntro;
		return 1;
	case 2:
		SetROIVisible(g_object2x4red, FALSE);
		SetROIVisible(g_object2x4grn, FALSE);
		BackgroundAudioManager()->RaiseVolume();
		return 1;
	case 4:
		if (action->GetObjectId() == InfomainScript::c_GoTo_RegBook ||
			action->GetObjectId() == InfomainScript::c_GoTo_RegBook_Red) {
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			m_infocenterState->m_unk0x74 = 14;
			return 1;
		}
		break;
	case 5:
		if (action->GetObjectId() == m_currentInfomainScript) {
			if (GameState()->GetCurrentAct() != LegoGameState::e_act3 && m_selectedCharacter != e_noCharacter) {
				GameState()->SetActor(m_selectedCharacter);
			}
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			m_infocenterState->m_unk0x74 = 14;
			return 1;
		}
		break;
	case 11:
		if (!m_infocenterState->HasRegistered() && m_currentInfomainScript != InfomainScript::c_Mama_All_Movie &&
			m_currentInfomainScript != InfomainScript::c_Papa_All_Movie &&
			m_currentInfomainScript != InfomainScript::c_Pepper_All_Movie &&
			m_currentInfomainScript != InfomainScript::c_Nick_All_Movie &&
			m_currentInfomainScript != InfomainScript::c_Laura_All_Movie) {
			m_infoManDialogueTimer = 1;
			PlayMusic(JukeboxScript::c_InformationCenter_Music);
		}

		m_infocenterState->m_unk0x74 = 2;
		SetROIVisible("infoman", TRUE);
		return 1;
	case 12:
		if (action->GetObjectId() == m_currentInfomainScript) {
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		}
	}

	result = 1;

	return result;
}

// FUNCTION: LEGO1 0x1006f4e0
void Infocenter::ReadyWorld()
{
	m_infoManDialogueTimer = 0;
	m_bookAnimationTimer = 0;
	m_unk0x1d4 = 0;
	m_unk0x1d6 = 0;

	MxStillPresenter* bg = (MxStillPresenter*) Find("MxStillPresenter", "Background_Bitmap");
	MxStillPresenter* bgRed = (MxStillPresenter*) Find("MxStillPresenter", "BackgroundRed_Bitmap");

	switch (GameState()->GetCurrentAct()) {
	case LegoGameState::e_act1:
		bg->Enable(TRUE);
		InitializeBitmaps();

		switch (m_infocenterState->m_unk0x74) {
		case 3:
			PlayCutscene(e_legoMovie, TRUE);
			m_infocenterState->m_unk0x74 = 0;
			return;
		case 4:
			m_infocenterState->m_unk0x74 = 2;
			if (!m_infocenterState->HasRegistered()) {
				m_bookAnimationTimer = 1;
			}

			PlayAction(InfomainScript::c_iicx18in_RunAnim);
			PlayMusic(JukeboxScript::c_InformationCenter_Music);
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			return;
		case 5:
		default: {
			PlayMusic(JukeboxScript::c_InformationCenter_Music);

			InfomainScript::Script script = m_infocenterState->GetNextReturnDialogue();
			PlayAction(script);

			if (script == InfomainScript::c_iicx26in_RunAnim) {
				m_unk0x1d6 = 1;
			}

			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);

			if (!m_infocenterState->HasRegistered()) {
				m_bookAnimationTimer = 1;
			}

			break;
		}
		case 8:
			PlayMusic(JukeboxScript::c_InformationCenter_Music);
			PlayAction(InfomainScript::c_iic043in_RunAnim);
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			return;
		case 0xf:
			m_infocenterState->m_unk0x74 = 2;
			if (!m_infocenterState->HasRegistered()) {
				m_bookAnimationTimer = 1;
			}

			PlayAction(InfomainScript::c_iicx17in_RunAnim);
			PlayMusic(JukeboxScript::c_InformationCenter_Music);
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			return;
		}
		break;
	case LegoGameState::e_act2: {
		if (m_infocenterState->m_unk0x74 == 8) {
			PlayMusic(JukeboxScript::c_InformationCenter_Music);
			bgRed->Enable(TRUE);
			PlayAction(InfomainScript::c_iic043in_RunAnim);
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			return;
		}

		LegoAct2State* state = (LegoAct2State*) GameState()->GetState("LegoAct2State");
		GameState()->FindLoadedAct();

		if (state && state->GetUnknown0x08() == 0x68) {
			bg->Enable(TRUE);
			PlayCutscene(e_badEndMovie, TRUE);
			m_infocenterState->m_unk0x74 = 0;
			return;
		}

		if (m_infocenterState->m_unk0x74 == 4) {
			bgRed->Enable(TRUE);

			if (GameState()->GetCurrentAct() == GameState()->GetLoadedAct()) {
				GameState()->m_currentArea = LegoGameState::e_act2main;
				GameState()->StopArea(LegoGameState::e_act2main);
				GameState()->m_currentArea = LegoGameState::e_infomain;
			}

			m_infocenterState->m_unk0x74 = 5;
			m_destLocation = LegoGameState::e_act2main;

			InfomainScript::Script script = m_infocenterState->GetNextReturnDialogue();
			PlayAction(script);

			InputManager()->DisableInputProcessing();
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			return;
		}

		PlayMusic(JukeboxScript::c_InformationCenter_Music);
		InfomainScript::Script script = m_infocenterState->GetNextReturnDialogue();
		PlayAction(script);
		bgRed->Enable(TRUE);
		break;
	}
	case LegoGameState::e_act3: {
		if (m_infocenterState->m_unk0x74 == 8) {
			PlayMusic(JukeboxScript::c_InformationCenter_Music);
			bgRed->Enable(TRUE);
			PlayAction(InfomainScript::c_iic043in_RunAnim);
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			return;
		}

		Act3State* state = (Act3State*) GameState()->GetState("Act3State");
		GameState()->FindLoadedAct();

		if (state && state->GetUnknown0x08() == 3) {
			bg->Enable(TRUE);
			PlayCutscene(e_badEndMovie, TRUE);
			m_infocenterState->m_unk0x74 = 0;
			return;
		}

		if (state && state->GetUnknown0x08() == 2) {
			bg->Enable(TRUE);
			PlayCutscene(e_goodEndMovie, TRUE);
			m_infocenterState->m_unk0x74 = 0;
			return;
		}

		if (m_infocenterState->m_unk0x74 == 4) {
			bgRed->Enable(TRUE);

			if (GameState()->GetCurrentAct() == GameState()->GetLoadedAct()) {
				GameState()->m_currentArea = LegoGameState::e_act3script;
				GameState()->StopArea(LegoGameState::e_act3script);
				GameState()->m_currentArea = LegoGameState::e_infomain;
			}

			m_infocenterState->m_unk0x74 = 5;
			m_destLocation = LegoGameState::e_act3script;

			InfomainScript::Script script = m_infocenterState->GetNextReturnDialogue();
			PlayAction(script);

			InputManager()->DisableInputProcessing();
			FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
			return;
		}

		PlayMusic(JukeboxScript::c_InformationCenter_Music);
		InfomainScript::Script script = m_infocenterState->GetNextReturnDialogue();
		PlayAction(script);
		bgRed->Enable(TRUE);
		break;
	}
	}

	m_infocenterState->m_unk0x74 = 11;
	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x1006f9a0
// FUNCTION: BETA10 0x1002ef2f
void Infocenter::InitializeBitmaps()
{
	m_radio.Initialize(TRUE);

	((MxPresenter*) Find(m_atomId, InfomainScript::c_LeftArrow_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_RightArrow_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Info_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Boat_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Race_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Pizza_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Gas_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Med_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Cop_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Mama_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Papa_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Pepper_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Nick_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Laura_Ctl))->Enable(TRUE);
	((MxPresenter*) Find(m_atomId, InfomainScript::c_Radio_Ctl))->Enable(TRUE);

	m_glowInfo[0].m_destCtl = (MxStillPresenter*) Find("MxStillPresenter", "Info_A_Bitmap");
	assert(m_glowInfo[0].m_destCtl);
	m_glowInfo[0].m_area = MxRect<MxS32>(391, 182, 427, 230);
	m_glowInfo[0].m_unk0x04 = 3;

	m_glowInfo[1].m_destCtl = (MxStillPresenter*) Find("MxStillPresenter", "Boat_A_Bitmap");
	assert(m_glowInfo[1].m_destCtl);
	m_glowInfo[1].m_area = MxRect<MxS32>(304, 225, 350, 268);
	m_glowInfo[1].m_unk0x04 = 10;

	m_glowInfo[2].m_destCtl = (MxStillPresenter*) Find("MxStillPresenter", "Race_A_Bitmap");
	assert(m_glowInfo[1].m_destCtl); // DECOMP: intentional typo
	m_glowInfo[2].m_area = MxRect<MxS32>(301, 133, 347, 181);
	m_glowInfo[2].m_unk0x04 = 11;

	m_glowInfo[3].m_destCtl = (MxStillPresenter*) Find("MxStillPresenter", "Pizza_A_Bitmap");
	assert(m_glowInfo[3].m_destCtl);
	m_glowInfo[3].m_area = MxRect<MxS32>(289, 182, 335, 225);
	m_glowInfo[3].m_unk0x04 = 12;

	m_glowInfo[4].m_destCtl = (MxStillPresenter*) Find("MxStillPresenter", "Gas_A_Bitmap");
	assert(m_glowInfo[4].m_destCtl);
	m_glowInfo[4].m_area = MxRect<MxS32>(350, 161, 391, 209);
	m_glowInfo[4].m_unk0x04 = 13;

	m_glowInfo[5].m_destCtl = (MxStillPresenter*) Find("MxStillPresenter", "Med_A_Bitmap");
	assert(m_glowInfo[5].m_destCtl);
	m_glowInfo[5].m_area = MxRect<MxS32>(392, 130, 438, 176);
	m_glowInfo[5].m_unk0x04 = 14;

	m_glowInfo[6].m_destCtl = (MxStillPresenter*) Find("MxStillPresenter", "Cop_A_Bitmap");
	assert(m_glowInfo[6].m_destCtl);
	m_glowInfo[6].m_area = MxRect<MxS32>(396, 229, 442, 272);
	m_glowInfo[6].m_unk0x04 = 15;

	m_frame = (MxStillPresenter*) Find("MxStillPresenter", "FrameHot_Bitmap");
	assert(m_frame);

	UpdateFrameHot(TRUE);
}

// FUNCTION: LEGO1 0x1006fd00
// FUNCTION: BETA10 0x1002f808
MxU8 Infocenter::HandleMouseMove(MxS32 p_x, MxS32 p_y)
{
	if (m_dragPresenter) {
		if (!m_dragPresenter->IsEnabled()) {
			MxS32 oldDisplayZ = m_dragPresenter->GetDisplayZ();

			m_dragPresenter->SetDisplayZ(1000);
			VideoManager()->SortPresenterList();
			m_dragPresenter->Enable(TRUE);
			m_dragPresenter->SetPosition(p_x, p_y);
			m_dragPresenter->SetDisplayZ(oldDisplayZ);
		}
		else {
			m_dragPresenter->SetPosition(p_x, p_y);
		}

		FUN_10070d10(p_x, p_y);
		return 1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1006fda0
// FUNCTION: BETA10 0x1002f907
MxLong Infocenter::HandleKeyPress(MxS8 p_key)
{
	MxLong result = 0;

	if (p_key == VK_SPACE && m_worldStarted) {
		switch (m_infocenterState->m_unk0x74) {
		case 0:
			StopCutscene();
			m_infocenterState->m_unk0x74 = 1;

			if (!m_infocenterState->HasRegistered()) {
				m_bookAnimationTimer = 1;
				return 1;
			}
			break;
		case 1:
		case 4:
			break;
		default: {
			InfomainScript::Script script = m_currentInfomainScript;
			StopCurrentAction();

			switch (m_infocenterState->m_unk0x74) {
			case 5:
			case 12:
				m_currentInfomainScript = script;
				return 1;
			default:
				m_infocenterState->m_unk0x74 = 2;
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

// FUNCTION: LEGO1 0x1006feb0
// FUNCTION: BETA10 0x1002fa12
MxU8 Infocenter::HandleButtonUp(MxS32 p_x, MxS32 p_y)
{
	if (m_dragPresenter) {
		MxControlPresenter* control = InputManager()->GetControlManager()->FUN_100294e0(p_x - 1, p_y - 1);

		switch (m_dragPresenter->GetAction()->GetObjectId()) {
		case InfomainScript::c_PepperHot_Bitmap:
			m_selectedCharacter = e_pepper;
			break;
		case InfomainScript::c_MamaHot_Bitmap:
			m_selectedCharacter = e_mama;
			break;
		case InfomainScript::c_PapaHot_Bitmap:
			m_selectedCharacter = e_papa;
			break;
		case InfomainScript::c_NickHot_Bitmap:
			m_selectedCharacter = e_nick;
			break;
		case InfomainScript::c_LauraHot_Bitmap:
			m_selectedCharacter = e_laura;
			break;
		}

		if (control != NULL) {
			m_infoManDialogueTimer = 0;

			switch (control->GetAction()->GetObjectId()) {
			case InfomainScript::c_Pepper_Ctl:
				if (m_selectedCharacter == e_pepper) {
					m_radio.Stop();
					BackgroundAudioManager()->Stop();
					PlayAction(InfomainScript::c_Pepper_All_Movie);
					m_unk0x1d4++;
				}
				break;
			case InfomainScript::c_Mama_Ctl:
				if (m_selectedCharacter == e_mama) {
					m_radio.Stop();
					BackgroundAudioManager()->Stop();
					PlayAction(InfomainScript::c_Mama_All_Movie);
					m_unk0x1d4++;
				}
				break;
			case InfomainScript::c_Papa_Ctl:
				if (m_selectedCharacter == e_papa) {
					m_radio.Stop();
					BackgroundAudioManager()->Stop();
					PlayAction(InfomainScript::c_Papa_All_Movie);
					m_unk0x1d4++;
				}
				break;
			case InfomainScript::c_Nick_Ctl:
				if (m_selectedCharacter == e_nick) {
					m_radio.Stop();
					BackgroundAudioManager()->Stop();
					PlayAction(InfomainScript::c_Nick_All_Movie);
					m_unk0x1d4++;
				}
				break;
			case InfomainScript::c_Laura_Ctl:
				if (m_selectedCharacter == e_laura) {
					m_radio.Stop();
					BackgroundAudioManager()->Stop();
					PlayAction(InfomainScript::c_Laura_All_Movie);
					m_unk0x1d4++;
				}
				break;
			}
		}
		else {
			if (m_unk0x1c8 != -1) {
				m_infoManDialogueTimer = 0;

				switch (m_glowInfo[m_unk0x1c8].m_unk0x04) {
				case 3:
					GameState()->SetActor(m_selectedCharacter);

					switch (m_selectedCharacter) {
					case e_pepper:
						PlayAction(InfomainScript::c_avo901in_RunAnim);
						break;
					case e_mama:
						PlayAction(InfomainScript::c_avo902in_RunAnim);
						break;
					case e_papa:
						PlayAction(InfomainScript::c_avo903in_RunAnim);
						break;
					case e_nick:
						PlayAction(InfomainScript::c_avo904in_RunAnim);
						break;
					case e_laura:
						PlayAction(InfomainScript::c_avo905in_RunAnim);
						break;
					}
					break;
				case 10:
					if (m_selectedCharacter) {
						m_destLocation = LegoGameState::e_jetraceExterior;
						m_infocenterState->m_unk0x74 = 5;
					}
					break;
				case 11:
					if (m_selectedCharacter) {
						m_destLocation = LegoGameState::e_carraceExterior;
						m_infocenterState->m_unk0x74 = 5;
					}
					break;
				case 12:
					if (m_selectedCharacter) {
						m_destLocation = LegoGameState::e_pizzeriaExterior;
						m_infocenterState->m_unk0x74 = 5;
					}
					break;
				case 13:
					if (m_selectedCharacter) {
						m_destLocation = LegoGameState::e_garageExterior;
						m_infocenterState->m_unk0x74 = 5;
					}
					break;
				case 14:
					if (m_selectedCharacter) {
						m_destLocation = LegoGameState::e_hospitalExterior;
						m_infocenterState->m_unk0x74 = 5;
					}
					break;
				case 15:
					if (m_selectedCharacter) {
						m_destLocation = LegoGameState::e_policeExterior;
						m_infocenterState->m_unk0x74 = 5;
					}
					break;
				}
			}
		}

		m_dragPresenter->Enable(FALSE);
		m_dragPresenter = NULL;

		if (m_infocenterState->m_unk0x74 == 5) {
			InfomainScript::Script dialogueToPlay;

			if (GameState()->GetCurrentAct() == LegoGameState::e_act1) {
				if (!m_infocenterState->HasRegistered()) {
					dialogueToPlay = InfomainScript::c_iic007in_PlayWav;
					m_infocenterState->m_unk0x74 = 2;
					m_destLocation = LegoGameState::e_undefined;
				}
				else {
					switch (m_selectedCharacter) {
					case e_pepper:
						dialogueToPlay = InfomainScript::c_avo901in_RunAnim;
						GameState()->SetActorId(m_selectedCharacter);
						break;
					case e_mama:
						dialogueToPlay = InfomainScript::c_avo902in_RunAnim;
						GameState()->SetActorId(m_selectedCharacter);
						break;
					case e_papa:
						dialogueToPlay = InfomainScript::c_avo903in_RunAnim;
						GameState()->SetActorId(m_selectedCharacter);
						break;
					case e_nick:
						dialogueToPlay = InfomainScript::c_avo904in_RunAnim;
						GameState()->SetActorId(m_selectedCharacter);
						break;
					case e_laura:
						dialogueToPlay = InfomainScript::c_avo905in_RunAnim;
						GameState()->SetActorId(m_selectedCharacter);
						break;
					default:
						assert(0);
						dialogueToPlay = m_infocenterState->GetNextLeaveDialogue();
						break;
					}

					InputManager()->DisableInputProcessing();
					InputManager()->SetUnknown336(TRUE);
				}
			}
			else {
				dialogueToPlay = m_infocenterState->GetNextLeaveDialogue();
			}

			PlayAction(dialogueToPlay);
		}

		UpdateFrameHot(TRUE);
		FUN_10070d10(0, 0);
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x10070370
// FUNCTION: BETA10 0x1002ffd4
MxU8 Infocenter::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	if (p_param.m_unk0x28 == 1) {
		m_infoManDialogueTimer = 0;

		InfomainScript::Script actionToPlay = InfomainScript::c_noneInfomain;
		StopCurrentAction();
		InfomainScript::Script characterBitmap = InfomainScript::c_noneInfomain;

		LegoGameState* state = GameState();

		switch (p_param.m_clickedObjectId) {
		case InfomainScript::c_LeftArrow_Ctl:
			m_infocenterState->m_unk0x74 = 14;
			StopCurrentAction();

			if (GameState()->GetCurrentAct() == LegoGameState::e_act1) {
				m_radio.Stop();
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
				m_destLocation = LegoGameState::e_elevbott;
			}
			else {
				MxU32 objectId = m_infocenterState->GetBricksterDialogue().Next();
				PlayAction((InfomainScript::Script) objectId);
			}

			break;
		case InfomainScript::c_RightArrow_Ctl:
			m_infocenterState->m_unk0x74 = 14;
			StopCurrentAction();

			if (GameState()->GetCurrentAct() == LegoGameState::e_act1) {
				m_radio.Stop();
				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
				m_destLocation = LegoGameState::e_infoscor;
			}
			else {
				MxU32 objectId = m_infocenterState->GetBricksterDialogue().Next();
				PlayAction((InfomainScript::Script) objectId);
			}

			break;
		case InfomainScript::c_Info_Ctl:
			actionToPlay = InfomainScript::c_iic007ra_PlayWav;
			m_radio.Stop();
			break;
		case InfomainScript::c_Door_Ctl:
			if (m_infocenterState->m_unk0x74 != 8) {
				actionToPlay = InfomainScript::c_iic043in_RunAnim;
				m_radio.Stop();
				m_infocenterState->m_unk0x74 = 8;
			}

			break;
		case InfomainScript::c_Boat_Ctl:
			actionToPlay = InfomainScript::c_ijs002ra_PlayWav;
			m_radio.Stop();
			break;
		case InfomainScript::c_Race_Ctl:
			actionToPlay = InfomainScript::c_irt001ra_PlayWav;
			m_radio.Stop();
			break;
		case InfomainScript::c_Pizza_Ctl:
			actionToPlay = InfomainScript::c_ipz006ra_PlayWav;
			m_radio.Stop();
			break;
		case InfomainScript::c_Gas_Ctl:
			actionToPlay = InfomainScript::c_igs004ra_PlayWav;
			m_radio.Stop();
			break;
		case InfomainScript::c_Med_Ctl:
			actionToPlay = InfomainScript::c_iho003ra_PlayWav;
			m_radio.Stop();
			break;
		case InfomainScript::c_Cop_Ctl:
			actionToPlay = InfomainScript::c_ips005ra_PlayWav;
			m_radio.Stop();
			break;
		case InfomainScript::c_BigInfo_Ctl:
			switch (state->GetCurrentAct()) {
			case LegoGameState::e_act1:
				if (state->m_previousArea) {
					switch (state->m_previousArea) {
					case LegoGameState::e_infodoor:
					case LegoGameState::e_regbook:
					case LegoGameState::e_infoscor:
						m_infocenterState->m_unk0x74 = 5;
						m_destLocation = state->m_previousArea;
						actionToPlay = (InfomainScript::Script) m_infocenterState->GetNextLeaveDialogue();
						m_radio.Stop();
						InputManager()->DisableInputProcessing();
						InputManager()->SetUnknown336(TRUE);
						break;
					case LegoGameState::e_elevbott:
					case LegoGameState::e_elevride:
					case LegoGameState::e_elevride2:
					case LegoGameState::e_elevopen:
					case LegoGameState::e_seaview:
					case LegoGameState::e_observe:
					case LegoGameState::e_elevdown:
						break;
					default:
						if (state->GetActorId() != LegoActor::c_none) {
							if (!m_infocenterState->HasRegistered()) {
								PlayAction(InfomainScript::c_iic007in_PlayWav);
								m_infocenterState->m_unk0x74 = 2;
							}
							else {
								m_infocenterState->m_unk0x74 = 5;
								m_destLocation = state->m_previousArea;
								actionToPlay = (InfomainScript::Script) m_infocenterState->GetNextLeaveDialogue();
								m_radio.Stop();
								InputManager()->DisableInputProcessing();
								InputManager()->SetUnknown336(TRUE);
							}
						}
						break;
					}
				}
				break;
			case LegoGameState::e_act2:
				m_infocenterState->m_unk0x74 = 5;
				m_destLocation = LegoGameState::e_act2main;
				actionToPlay = (InfomainScript::Script) m_infocenterState->GetNextLeaveDialogue();
				InputManager()->DisableInputProcessing();
				InputManager()->SetUnknown336(TRUE);
				break;
			case LegoGameState::e_act3:
				m_infocenterState->m_unk0x74 = 5;
				m_destLocation = LegoGameState::e_act3script;
				actionToPlay = (InfomainScript::Script) m_infocenterState->GetNextLeaveDialogue();
				InputManager()->DisableInputProcessing();
				InputManager()->SetUnknown336(TRUE);
				break;
			}
			break;
		case InfomainScript::c_Book_Ctl:
			m_destLocation = LegoGameState::e_regbook;
			m_infocenterState->m_unk0x74 = 4;
			actionToPlay = GameState()->GetCurrentAct() != LegoGameState::e_act1 ? InfomainScript::c_GoTo_RegBook_Red
																				 : InfomainScript::c_GoTo_RegBook;
			m_radio.Stop();
			GameState()->m_unk0x42c = GameState()->m_previousArea;
			InputManager()->DisableInputProcessing();
			break;
		case InfomainScript::c_Mama_Ctl:
			characterBitmap = InfomainScript::c_MamaHot_Bitmap;
			UpdateFrameHot(FALSE);
			break;
		case InfomainScript::c_Papa_Ctl:
			characterBitmap = InfomainScript::c_PapaHot_Bitmap;
			UpdateFrameHot(FALSE);
			break;
		case InfomainScript::c_Pepper_Ctl:
			characterBitmap = InfomainScript::c_PepperHot_Bitmap;
			UpdateFrameHot(FALSE);
			break;
		case InfomainScript::c_Nick_Ctl:
			characterBitmap = InfomainScript::c_NickHot_Bitmap;
			UpdateFrameHot(FALSE);
			break;
		case InfomainScript::c_Laura_Ctl:
			characterBitmap = InfomainScript::c_LauraHot_Bitmap;
			UpdateFrameHot(FALSE);
			break;
		}

		if (actionToPlay != InfomainScript::c_noneInfomain) {
			PlayAction(actionToPlay);
		}

		if (characterBitmap != InfomainScript::c_noneInfomain) {
			m_dragPresenter = (MxStillPresenter*) Find(m_atomId, characterBitmap);
			assert(m_dragPresenter);
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x10070870
// FUNCTION: BETA10 0x1003039e
MxLong Infocenter::HandleNotification0(MxNotificationParam& p_param)
{
	// This function has changed significantly since BETA10

	MxCore* sender = p_param.GetSender();

	if (sender == NULL) {
		if (m_infocenterState->m_unk0x74 == 8) {
			m_infoManDialogueTimer = 0;
			StopCutscene();
			PlayAction(InfomainScript::c_iic043in_RunAnim);
		}
	}
	else if (sender->IsA("MxEntity") && m_infocenterState->m_unk0x74 != 5 && m_infocenterState->m_unk0x74 != 12) {
		switch (((MxEntity*) sender)->GetEntityId()) {
		case 5: {
			m_infoManDialogueTimer = 0;

			InfomainScript::Script objectId;
			if (GameState()->GetCurrentAct() != LegoGameState::e_act1) {
				objectId = (InfomainScript::Script) m_infocenterState->GetExitDialogueAct23().Next();
			}
			else {
				objectId = (InfomainScript::Script) m_infocenterState->GetExitDialogueAct1().Next();
			}

			PlayAction(objectId);
			SetROIVisible(g_object2x4red, FALSE);
			SetROIVisible(g_object2x4grn, FALSE);
			return 1;
		}
		case 6:
			if (m_infocenterState->m_unk0x74 == 8) {
				StopCurrentAction();
				SetROIVisible(g_object2x4red, FALSE);
				SetROIVisible(g_object2x4grn, FALSE);
				m_infocenterState->m_unk0x74 = 2;
				PlayAction(InfomainScript::c_iicb28in_RunAnim);
				return 1;
			}
		case 7:
			if (m_infocenterState->m_unk0x74 == 8) {
				if (m_infocenterState->HasRegistered()) {
					GameState()->Save(0);
				}

				m_infocenterState->m_unk0x74 = 12;
				PlayAction(InfomainScript::c_iic046in_RunAnim);
				InputManager()->DisableInputProcessing();
				InputManager()->SetUnknown336(TRUE);
				return 1;
			}
		}
	}
	else {
		if (sender->IsA("Radio") && m_radio.GetState()->IsActive()) {
			if (m_currentInfomainScript == InfomainScript::c_Mama_All_Movie ||
				m_currentInfomainScript == InfomainScript::c_Papa_All_Movie ||
				m_currentInfomainScript == InfomainScript::c_Pepper_All_Movie ||
				m_currentInfomainScript == InfomainScript::c_Nick_All_Movie ||
				m_currentInfomainScript == InfomainScript::c_Laura_All_Movie ||
				m_currentInfomainScript == InfomainScript::c_iic007ra_PlayWav ||
				m_currentInfomainScript == InfomainScript::c_ijs002ra_PlayWav ||
				m_currentInfomainScript == InfomainScript::c_irt001ra_PlayWav ||
				m_currentInfomainScript == InfomainScript::c_ipz006ra_PlayWav ||
				m_currentInfomainScript == InfomainScript::c_igs004ra_PlayWav ||
				m_currentInfomainScript == InfomainScript::c_iho003ra_PlayWav ||
				m_currentInfomainScript == InfomainScript::c_ips005ra_PlayWav) {
				StopCurrentAction();
			}
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x10070aa0
// FUNCTION: BETA10 0x10030508
void Infocenter::Enable(MxBool p_enable)
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

// FUNCTION: LEGO1 0x10070af0
MxResult Infocenter::Tickle()
{
	if (m_worldStarted == FALSE) {
		LegoWorld::Tickle();
		return SUCCESS;
	}

	if (m_infoManDialogueTimer != 0 && (m_infoManDialogueTimer += 100) > 25000) {
		PlayAction(InfomainScript::c_iicx17in_RunAnim);
		m_infoManDialogueTimer = 0;
	}

	if (m_bookAnimationTimer != 0 && (m_bookAnimationTimer += 100) > 3000) {
		PlayBookAnimation();
		m_bookAnimationTimer = 1;
	}

	if (m_unk0x1d6 != 0) {
		m_unk0x1d6 += 100;

		if (m_unk0x1d6 > 3400 && m_unk0x1d6 < 3650) {
			ControlManager()->FUN_100293c0(InfomainScript::c_BigInfo_Ctl, m_atomId.GetInternal(), 1);
		}
		else if (m_unk0x1d6 > 3650 && m_unk0x1d6 < 3900) {
			ControlManager()->FUN_100293c0(InfomainScript::c_BigInfo_Ctl, m_atomId.GetInternal(), 0);
		}
		else if (m_unk0x1d6 > 3900 && m_unk0x1d6 < 4150) {
			ControlManager()->FUN_100293c0(InfomainScript::c_BigInfo_Ctl, m_atomId.GetInternal(), 1);
		}
		else if (m_unk0x1d6 > 4400) {
			ControlManager()->FUN_100293c0(InfomainScript::c_BigInfo_Ctl, m_atomId.GetInternal(), 0);
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
	SetAppCursor(e_cursorNone);
	VideoManager()->GetDisplaySurface()->ClearScreen();

	if (m_currentCutscene != e_noIntro) {
		// check if the cutscene is an ending
		if (m_currentCutscene >= e_badEndMovie && m_currentCutscene <= e_goodEndMovie) {
			Reset();
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
	SetAppCursor(e_cursorArrow);
	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x10070d00
MxBool Infocenter::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x10070d10
// FUNCTION: BETA10 0x100307d4
void Infocenter::FUN_10070d10(MxS32 p_x, MxS32 p_y)
{
	MxS16 i;
	for (i = 0; i < (MxS32) (sizeof(m_glowInfo) / sizeof(m_glowInfo[0])); i++) {
		MxS32 right = m_glowInfo[i].m_area.GetRight();
		MxS32 bottom = m_glowInfo[i].m_area.GetBottom();
		MxS32 left = m_glowInfo[i].m_area.GetLeft();
		MxS32 top = m_glowInfo[i].m_area.GetTop();

		if (left <= p_x && p_x <= right && top <= p_y && p_y <= bottom) {
			break;
		}
	}

	if (i == 7) {
		i = -1;
	}

	if (i != m_unk0x1c8) {
		if (m_unk0x1c8 != -1) {
			m_glowInfo[m_unk0x1c8].m_destCtl->Enable(FALSE);
		}

		m_unk0x1c8 = i;
		if (i != -1) {
			m_glowInfo[i].m_destCtl->Enable(TRUE);
		}
	}
}

// FUNCTION: LEGO1 0x10070dc0
// FUNCTION: BETA10 0x10030911
void Infocenter::UpdateFrameHot(MxBool p_display)
{
	if (p_display) {
		MxS32 x, y;

		switch (GameState()->GetActorId()) {
		case LegoActor::c_pepper:
			x = 302;
			y = 81;
			break;
		case LegoActor::c_mama:
			x = 204;
			y = 81;
			break;
		case LegoActor::c_papa:
			x = 253;
			y = 81;
			break;
		case LegoActor::c_nick:
			x = 353;
			y = 81;
			break;
		case LegoActor::c_laura:
			x = 399;
			y = 81;
			break;
		default:
			return;
		}

		MxS32 originalDisplayZ = m_frame->GetDisplayZ();

		m_frame->SetDisplayZ(1000);
		VideoManager()->SortPresenterList();

		m_frame->Enable(TRUE);
		m_frame->SetPosition(x, y);
		m_frame->SetDisplayZ(originalDisplayZ);
	}
	else {
		if (m_frame) {
			m_frame->Enable(FALSE);
		}
	}
}

// FUNCTION: LEGO1 0x10070e90
void Infocenter::Reset()
{
	switch (GameState()->GetCurrentAct()) {
	case LegoGameState::e_act2:
		Lego()->RemoveWorld(*g_act2mainScript, 0);
		break;
	case LegoGameState::e_act3:
		Lego()->RemoveWorld(*g_act3Script, 0);
		break;
	}

	PlantManager()->ClearCounters();
	BuildingManager()->ClearCounters();
	AnimationManager()->Reset(FALSE);
	CharacterManager()->ReleaseAllActors();
	GameState()->SetCurrentAct(LegoGameState::e_act1);
	GameState()->m_previousArea = LegoGameState::e_undefined;
	GameState()->m_unk0x42c = LegoGameState::e_undefined;

	InitializeBitmaps();
	m_selectedCharacter = e_pepper;

	GameState()->SetActor(e_pepper);

	HelicopterState* state = (HelicopterState*) GameState()->GetState("HelicopterState");

	if (state) {
		state->Reset();
	}
}

// FUNCTION: LEGO1 0x10070f60
MxBool Infocenter::Escape()
{
	if (m_infocenterState != NULL) {
		MxU32 val = m_infocenterState->m_unk0x74;

		if (val == 0) {
			StopCutscene();
			m_infocenterState->m_unk0x74 = 1;
		}
		else if (val == 13) {
			StopCredits();
		}
		else if (val != 8) {
			m_infocenterState->m_unk0x74 = 8;

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

// FUNCTION: LEGO1 0x10071030
void Infocenter::StartCredits()
{
	MxPresenter* presenter;

	while (!m_set0xa8.empty()) {
		MxCoreSet::iterator it = m_set0xa8.begin();
		MxCore* object = *it;
		m_set0xa8.erase(it);

		if (object->IsA("MxPresenter")) {
			presenter = (MxPresenter*) object;
			MxDSAction* action = presenter->GetAction();

			if (action) {
				ApplyMask(action, MxDSAction::c_world, FALSE);
				presenter->EndAction();
			}
		}
		else {
			delete object;
		}
	}

	MxPresenterListCursor cursor(&m_controlPresenters);

	while (cursor.First(presenter)) {
		cursor.Detach();

		MxDSAction* action = presenter->GetAction();
		if (action) {
			ApplyMask(action, MxDSAction::c_world, FALSE);
			presenter->EndAction();
		}
	}

	BackgroundAudioManager()->Stop();

	MxS16 i = 0;
	do {
		if (m_infocenterState->GetNameLetter(i) != NULL) {
			m_infocenterState->GetNameLetter(i)->Enable(FALSE);
		}
		i++;
	} while (i < m_infocenterState->GetMaxNameLength());

	VideoManager()->FUN_1007c520();
	GetViewManager()->RemoveAll(NULL);

	InvokeAction(Extra::e_opendisk, *g_creditsScript, CreditsScript::c_LegoCredits, NULL);
	SetAppCursor(e_cursorArrow);
}

// FUNCTION: LEGO1 0x10071250
void Infocenter::StopCredits()
{
	MxDSAction action;
	action.SetObjectId(CreditsScript::c_LegoCredits);
	action.SetAtomId(*g_creditsScript);
	action.SetUnknown24(-2);
	DeleteObject(action);
}

// FUNCTION: LEGO1 0x10071300
// FUNCTION: BETA10 0x1002ee8c
void Infocenter::PlayAction(InfomainScript::Script p_script)
{
	MxDSAction action;
	action.SetObjectId(p_script);
	action.SetAtomId(*g_infomainScript);
	StopCurrentAction();

	m_currentInfomainScript = p_script;
	BackgroundAudioManager()->LowerVolume();
	Start(&action);
}

// FUNCTION: LEGO1 0x100713d0
void Infocenter::StopCurrentAction()
{
	if (m_currentInfomainScript != InfomainScript::c_noneInfomain) {
		MxDSAction action;
		action.SetObjectId(m_currentInfomainScript);
		action.SetAtomId(*g_infomainScript);
		action.SetUnknown24(-2);
		DeleteObject(action);
		m_currentInfomainScript = InfomainScript::c_noneInfomain;
	}
}

// FUNCTION: LEGO1 0x100714a0
void Infocenter::PlayBookAnimation()
{
	MxDSAction action;
	action.SetObjectId(SndanimScript::c_BookWig_Flic);
	action.SetAtomId(*g_sndAnimScript);
	Start(&action);
}

// FUNCTION: LEGO1 0x10071550
void Infocenter::StopBookAnimation()
{
	MxDSAction action;
	action.SetObjectId(SndanimScript::c_BookWig_Flic);
	action.SetAtomId(*g_sndAnimScript);
	action.SetUnknown24(-2);
	DeleteObject(action);
}

// FUNCTION: LEGO1 0x10071600
InfocenterState::InfocenterState()
{
	m_exitDialogueAct1 = Playlist((MxU32*) g_exitDialogueAct1, sizeOfArray(g_exitDialogueAct1), Playlist::e_loop);
	m_exitDialogueAct23 =
		Playlist((MxU32*) g_exitDialogueAct23, sizeOfArray(g_exitDialogueAct23) - 1, Playlist::e_loop);

	m_returnDialogue[LegoGameState::e_act1] =
		Playlist((MxU32*) g_returnDialogueAct1, sizeOfArray(g_returnDialogueAct1) - 1, Playlist::e_loop);

	m_returnDialogue[LegoGameState::e_act2] =
		Playlist((MxU32*) g_returnDialogueAct2, sizeOfArray(g_returnDialogueAct2) - 1, Playlist::e_loop);

	m_returnDialogue[LegoGameState::e_act3] =
		Playlist((MxU32*) g_returnDialogueAct3, sizeOfArray(g_returnDialogueAct3), Playlist::e_loop);

	m_leaveDialogue[LegoGameState::e_act1] =
		Playlist((MxU32*) g_leaveDialogueAct1, sizeOfArray(g_leaveDialogueAct1), Playlist::e_loop);

	m_leaveDialogue[LegoGameState::e_act2] =
		Playlist((MxU32*) g_leaveDialogueAct2, sizeOfArray(g_leaveDialogueAct2), Playlist::e_loop);

	m_leaveDialogue[LegoGameState::e_act3] =
		Playlist((MxU32*) g_leaveDialogueAct3, sizeOfArray(g_leaveDialogueAct3) - 1, Playlist::e_loop);

	m_bricksterDialogue = Playlist((MxU32*) g_bricksterDialogue, sizeOfArray(g_bricksterDialogue), Playlist::e_loop);

	memset(m_letters, 0, sizeof(m_letters));
}

// FUNCTION: LEGO1 0x10071920
InfocenterState::~InfocenterState()
{
	MxS16 i = 0;
	do {
		if (GetNameLetter(i) != NULL) {
			delete GetNameLetter(i)->GetAction();
			delete GetNameLetter(i);
		}
		i++;
	} while (i < GetMaxNameLength());
}
