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
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxtimer.h"
#include "mxtransitionmanager.h"
#include "regbook_actions.h"

DECOMP_SIZE_ASSERT(RegistrationBook, 0x2d0)

// GLOBAL: LEGO1 0x100d9924
const char* g_infoman = "infoman";

// FUNCTION: LEGO1 0x10076d20
RegistrationBook::RegistrationBook() : m_unk0xf8(0x80000000), m_unk0xfc(1)
{
	memset(m_alphabet, 0, sizeof(m_alphabet));
	memset(m_name, 0, sizeof(m_name));

	// May not be part of the struct, but then it would need packing
	m_unk0x280.m_unk0x0e = 0;

	memset(m_checkmark, 0, sizeof(m_checkmark));
	memset(&m_unk0x280, -1, sizeof(m_unk0x280) - 2);

	m_unk0x2b8 = 0;
	m_infocenterState = NULL;

	NotificationManager()->Register(this);

	m_unk0x2c1 = 0;
	m_unk0x2c4 = 0;
	m_unk0x2c8 = 0;
	m_unk0x2cc = 0;
}

// STUB: LEGO1 0x10076f50
RegistrationBook::~RegistrationBook()
{
	// TODO
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
			m_unk0xf8 = Timer()->GetTime();
			result = HandleKeyPress(((LegoEventNotificationParam&) p_param).GetKey());
			break;
		case c_notificationButtonDown:
			m_unk0xf8 = Timer()->GetTime();
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

// STUB: LEGO1 0x10077210
MxLong RegistrationBook::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	return 0;
}

// STUB: LEGO1 0x100772d0
MxLong RegistrationBook::HandleKeyPress(MxS8 p_key)
{
	return 0;
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

// STUB: LEGO1 0x100775c0
void RegistrationBook::FUN_100775c0(MxS16 p_playerIndex)
{
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
			infoman->SetUnknown0x0c(0);
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

// STUB: LEGO1 0x10077fd0
MxResult RegistrationBook::Tickle()
{
	if (!m_worldStarted) {
		LegoWorld::Tickle();
	}
	else {
		// TODO
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

// FUNCTION: LEGO1 0x100783e0
MxBool RegistrationBook::VTable0x64()
{
	DeleteObjects(&m_atom, RegbookScript::c_iic006in_RunAnim, RegbookScript::c_iic008in_PlayWav);
	return TRUE;
}
