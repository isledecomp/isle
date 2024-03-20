#include "registrationbook.h"

#include "infocenterstate.h"
#include "jukebox_actions.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxdisplaysurface.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "regbook_actions.h"

DECOMP_SIZE_ASSERT(RegistrationBook, 0x2d0)

// GLOBAL: LEGO1 0x100d9924
const char* g_infoman = "infoman";

// GLOBAL: LEGO1 0x100f7964
MxLong g_checkboxBlinkTimer = 0;

// GLOBAL: LEGO1 0x100f7968
MxBool g_nextCheckbox = FALSE;

// FUNCTION: LEGO1 0x10076d20
RegistrationBook::RegistrationBook() : m_registerDialogueTimer(0x80000000), m_unk0xfc(1)
{
	memset(m_alphabet, 0, sizeof(m_alphabet));
	memset(m_name, 0, sizeof(m_name));
	m_unk0x280.m_cursorPos = 0;

	memset(m_checkmark, 0, sizeof(m_checkmark));
	memset(&m_unk0x280, -1, sizeof(m_unk0x280) - 2);

	m_unk0x2b8 = 0;
	m_infocenterState = NULL;

	NotificationManager()->Register(this);

	m_unk0x2c1 = 0;
	m_checkboxHilite = NULL;
	m_checkboxSurface = NULL;
	m_checkboxNormal = NULL;
}

// FUNCTION: LEGO1 0x10076f50
RegistrationBook::~RegistrationBook()
{
	for (MxS16 i = 0; i < 10; i++) {
		for (MxS16 j = 0; j < 7; j++) {
			if (m_name[i][j] != NULL) {
				delete m_name[i][j]->GetAction();
				delete m_name[i][j];
				m_name[i][j] = NULL;
			}
		}
	}

	InputManager()->UnRegister(this);
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);

	if (m_checkboxNormal) {
		m_checkboxNormal->Release();
	}
}

// FUNCTION: LEGO1 0x10077060
MxResult RegistrationBook::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);

	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
		SetIsWorldActive(FALSE);
		InputManager()->Register(this);

		GameState()->SetCurrentArea(LegoGameState::e_regbook);
		GameState()->StopArea(LegoGameState::e_previousArea);

		m_infocenterState = (InfocenterState*) GameState()->GetState("InfocenterState");
	}

	return result;
}

// FUNCTION: LEGO1 0x100770e0
MxLong RegistrationBook::Notify(MxParam& p_param)
{
	MxLong result = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetType()) {
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationKeyPress:
			m_registerDialogueTimer = Timer()->GetTime();
			result = HandleKeyPress(((LegoEventNotificationParam&) p_param).GetKey());
			break;
		case c_notificationButtonDown:
			m_registerDialogueTimer = Timer()->GetTime();
			break;
		case c_notificationClick:
			result = HandleClick((LegoControlManagerEvent&) p_param);
			break;
		case c_notificationType19:
			result = HandleNotification19(p_param);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(LegoGameState::e_infomain);
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x10077210
MxLong RegistrationBook::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	if (p_param.GetAction()->GetAtomId() != m_atom) {
		return 0;
	}

	switch ((MxS32) p_param.GetAction()->GetObjectId()) {
	case RegbookScript::c_Textures:
		m_unk0x2c1 = 0;

		if (m_unk0x2b8 == 0) {
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		}
		break;
	case RegbookScript::c_iic006in_RunAnim:
	case RegbookScript::c_iic007in_PlayWav:
	case RegbookScript::c_iic008in_PlayWav:
		BackgroundAudioManager()->RaiseVolume();
		m_registerDialogueTimer = Timer()->GetTime();
		break;
	}

	return 1;
}

// FUNCTION: LEGO1 0x100772d0
MxLong RegistrationBook::HandleKeyPress(MxU8 p_key)
{
	MxS16 key;
	if (p_key >= 'a' && p_key <= 'z') {
		key = p_key - ' ';
	}
	else {
		key = p_key;
	}

	if ((key < 'A' || key > 'Z') && key != '\b') {
		if (key == ' ') {
			DeleteObjects(&m_atom, RegbookScript::c_iic006in_RunAnim, RegbookScript::c_iic008in_PlayWav);
			BackgroundAudioManager()->RaiseVolume();
		}
	}
	else if (key != '\b' && m_unk0x280.m_cursorPos < 7) {
		m_name[0][m_unk0x280.m_cursorPos] = m_alphabet[key - 'A']->Clone();

		if (m_name[0][m_unk0x280.m_cursorPos] != NULL) {
			m_alphabet[key - 'A']->GetAction()->SetUnknown24(m_alphabet[key - 'A']->GetAction()->GetUnknown24() + 1);
			m_name[0][m_unk0x280.m_cursorPos]->Enable(TRUE);
			m_name[0][m_unk0x280.m_cursorPos]->SetTickleState(MxPresenter::e_repeating);
			m_name[0][m_unk0x280.m_cursorPos]->SetPosition(m_unk0x280.m_cursorPos * 23 + 343, 121);

			if (m_unk0x280.m_cursorPos == 0) {
				m_checkmark[0]->Enable(TRUE);
			}

			m_unk0x280.m_letters[m_unk0x280.m_cursorPos] = key - 'A';
			m_unk0x280.m_cursorPos++;
		}
	}
	else {
		if (key == '\b' && m_unk0x280.m_cursorPos > 0) {
			m_unk0x280.m_cursorPos--;

			m_name[0][m_unk0x280.m_cursorPos]->Enable(FALSE);

			delete m_name[0][m_unk0x280.m_cursorPos];
			m_name[0][m_unk0x280.m_cursorPos] = NULL;

			if (m_unk0x280.m_cursorPos == 0) {
				m_checkmark[0]->Enable(FALSE);
			}

			m_unk0x280.m_letters[m_unk0x280.m_cursorPos] = -1;
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x100774a0
MxLong RegistrationBook::HandleClick(LegoControlManagerEvent& p_param)
{
	MxS16 unk0x28 = p_param.GetUnknown0x28();

	if (unk0x28 >= 1 && unk0x28 <= 28) {
		if (p_param.GetClickedObjectId() == RegbookScript::c_Alphabet_Ctl) {
			if (unk0x28 == 28) {
				DeleteObjects(&m_atom, RegbookScript::c_iic006in_RunAnim, RegbookScript::c_iic008in_PlayWav);

				if (GameState()->GetCurrentAct() == LegoGameState::e_act1) {
					m_infocenterState->SetUnknown0x74(15);
				}
				else {
					m_infocenterState->SetUnknown0x74(2);
				}

				TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			}
			else {
				if (unk0x28 > 28) {
					return 1;
				}

				HandleKeyPress(unk0x28 < 27 ? unk0x28 + 64 : 8);
			}
		}
		else {
			InputManager()->DisableInputProcessing();
			DeleteObjects(&m_atom, RegbookScript::c_iic006in_RunAnim, RegbookScript::c_iic008in_PlayWav);

			MxS16 i;
			for (i = 0; i < 10; i++) {
				if (m_checkmark[i]->GetAction()->GetObjectId() == p_param.GetClickedObjectId()) {
					break;
				}
			}

			FUN_100775c0(i);
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x100775c0
void RegistrationBook::FUN_100775c0(MxS16 p_playerIndex)
{
	if (m_infocenterState->HasRegistered()) {
		GameState()->Save(0);
	}

	// TODO: structure incorrect
	MxS16 player = p_playerIndex == 0 ? GameState()->FindPlayer(*(LegoGameState::Username*) &m_unk0x280.m_letters)
									  : p_playerIndex - 1;

	switch (player) {
	case 0:
		if (!m_infocenterState->HasRegistered()) {
			GameState()->SwitchPlayer(0);
			WriteInfocenterLetters(1);
			FUN_100778c0();
		}
		break;
	case -1:
		GameState()->Init();

		PlayAction(RegbookScript::c_Textures);

		m_unk0x2c1 = 1;

		// TOOD: structure incorrect
		GameState()->AddPlayer(*(LegoGameState::Username*) &m_unk0x280.m_letters);
		GameState()->Save(0);

		WriteInfocenterLetters(0);
		GameState()->SerializePlayersInfo(2);
		FUN_100778c0();
		break;
	default:
		GameState()->Init();

		PlayAction(RegbookScript::c_Textures);

		m_unk0x2c1 = 1;

		GameState()->SwitchPlayer(player);

		WriteInfocenterLetters(player + 1);
		GameState()->SerializePlayersInfo(2);
		FUN_100778c0();
		break;
	}

	m_infocenterState->SetUnknown0x74(4);
	if (m_unk0x2b8 == 0 && m_unk0x2c1 == 0) {
		DeleteObjects(&m_atom, RegbookScript::c_iic006in_RunAnim, RegbookScript::c_iic008in_PlayWav);
		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
	}
}

// FUNCTION: LEGO1 0x10077860
void RegistrationBook::WriteInfocenterLetters(MxS16 p_user)
{
	for (MxS16 i = 0; i < 7; i++) {
		delete m_infocenterState->GetNameLetter(i);
		m_infocenterState->SetNameLetter(i, m_name[p_user][i]);
		m_name[p_user][i] = NULL;
	}
}

// STUB: LEGO1 0x100778c0
void RegistrationBook::FUN_100778c0()
{
	// TODO
}

// FUNCTION: LEGO1 0x10077cc0
void RegistrationBook::ReadyWorld()
{
	LegoGameState* gameState = GameState();
	gameState->GetHistory()->WriteScoreHistory();
	MxS16 i;

	PlayMusic(JukeboxScript::c_InformationCenter_Music);

	char letterBuffer[] = "A_Bitmap";
	for (i = 0; i < 26; i++) {
		m_alphabet[i] = (MxStillPresenter*) Find("MxStillPresenter", letterBuffer);

		// We need to loop through the entire alphabet,
		// so increment the first char of the bitmap name
		letterBuffer[0]++;
	}

	// Now we have to do the checkmarks
	char checkmarkBuffer[] = "Check0_Ctl";
	for (i = 0; i < 10; i++) {
		m_checkmark[i] = (MxControlPresenter*) Find("MxControlPresenter", checkmarkBuffer);

		// Just like in the prior letter loop,
		// we need to increment the fifth char
		// to get the next checkmark bitmap
		checkmarkBuffer[5]++;
	}

	LegoGameState::Username* players = GameState()->m_players;

	for (i = 1; i <= GameState()->m_playerCount; i++) {
		for (MxS16 j = 0; j < 7; j++) {
			if (players[i - 1].m_letters[j] != -1) {
				if (j == 0) {
					m_checkmark[i]->Enable(TRUE);
				}

				// Start building the player names using a two-dimensional array
				m_name[i][j] = m_alphabet[players[i - 1].m_letters[j]]->Clone();

				// Enable the presenter to actually show the letter in the grid
				m_name[i][j]->Enable(TRUE);

				m_name[i][j]->SetTickleState(MxPresenter::e_repeating);
				m_name[i][j]->SetPosition(23 * j + 343, 27 * i + 121);
			}
		}
	}

	if (m_infocenterState->HasRegistered()) {
		PlayAction(RegbookScript::c_iic008in_PlayWav);

		LegoROI* infoman = FindROI(g_infoman);
		if (infoman != NULL) {
			infoman->SetVisibility(FALSE);
		}
	}
	else {
		PlayAction(RegbookScript::c_iic006in_RunAnim);
	}
}

inline void RegistrationBook::PlayAction(MxU32 p_objectId)
{
	MxDSAction action;
	action.SetAtomId(*g_regbookScript);
	action.SetObjectId(p_objectId);

	BackgroundAudioManager()->LowerVolume();
	Start(&action);
}

// FUNCTION: LEGO1 0x10077fd0
MxResult RegistrationBook::Tickle()
{
	if (!m_worldStarted) {
		LegoWorld::Tickle();
	}
	else {
		MxLong time = Timer()->GetTime();
		if (m_registerDialogueTimer != 0x80000000 && m_registerDialogueTimer + 30000 <= time) {
			m_registerDialogueTimer = 0x80000000;
			PlayAction(RegbookScript::c_iic007in_PlayWav);
		}

		if (g_checkboxBlinkTimer + 500 <= time) {
			g_checkboxBlinkTimer = time;

			if (m_checkboxHilite) {
				DDBLTFX op;
				op.dwSize = sizeof(op);
				op.dwROP = 0xcc0020;

				if (g_nextCheckbox) {
					m_checkboxSurface->Blt(NULL, m_checkboxHilite, NULL, DDBLT_ROP, &op);
				}
				else {
					m_checkboxSurface->Blt(NULL, m_checkboxNormal, NULL, DDBLT_ROP, &op);
				}
			}
			else {
				CreateSurface();
			}

			g_nextCheckbox = !g_nextCheckbox;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10078180
void RegistrationBook::Enable(MxBool p_enable)
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

// STUB: LEGO1 0x100781d0
MxLong RegistrationBook::HandleNotification19(MxParam& p_param)
{
	return 0;
}

// FUNCTION: LEGO1 0x10078350
MxBool RegistrationBook::CreateSurface()
{
	MxCompositePresenterList* list = m_checkmark[0]->GetList();
	MxStillPresenter *presenter, *uninitialized;

	if (list) {
		if (list->begin() != list->end()) {
			presenter = (MxStillPresenter*) list->front();
		}
		else {
			presenter = uninitialized; // intentionally uninitialized variable
		}

		if (presenter) {
			m_checkboxSurface = presenter->VTable0x78();
		}

		presenter = (MxStillPresenter*) Find("MxStillPresenter", "CheckHiLite_Bitmap");
		if (presenter) {
			m_checkboxHilite = presenter->VTable0x78();
		}

		if (m_checkboxSurface && m_checkboxHilite) {
			m_checkboxNormal = MxDisplaySurface::CopySurface(m_checkboxSurface);
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x100783e0
MxBool RegistrationBook::VTable0x64()
{
	DeleteObjects(&m_atom, RegbookScript::c_iic006in_RunAnim, RegbookScript::c_iic008in_PlayWav);
	return TRUE;
}
