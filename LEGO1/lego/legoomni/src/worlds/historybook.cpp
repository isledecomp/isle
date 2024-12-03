#include "historybook.h"

#include "jukebox.h"
#include "jukebox_actions.h"
#include "legocontrolmanager.h"
#include "legoinputmanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstillpresenter.h"
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(HistoryBook, 0x3e4)

// FUNCTION: LEGO1 0x100822f0
HistoryBook::HistoryBook()
{
	memset(m_alphabet, 0, sizeof(m_alphabet));
	memset(m_names, 0, sizeof(m_names));
	memset(m_scores, 0, sizeof(m_scores));
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x100824d0
// FUNCTION: BETA10 0x1002b63e
HistoryBook::~HistoryBook()
{
	for (MxS16 scoreIndex = 0; scoreIndex < GameState()->m_history.GetCount(); scoreIndex++) {
		if (m_scores[scoreIndex]) {
			delete m_scores[scoreIndex]->GetAction();
			delete m_scores[scoreIndex];
			m_scores[scoreIndex] = NULL;
		}

		for (MxS16 letterIndex = 0; letterIndex < (MxS16) sizeOfArray(m_names[0]); letterIndex++) {
			if (m_names[scoreIndex][letterIndex]) {
				delete m_names[scoreIndex][letterIndex]->GetAction();
				delete m_names[scoreIndex][letterIndex];
				m_names[scoreIndex][letterIndex] = NULL;
			}
		}
	}

	InputManager()->UnRegister(this);
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10082610
MxResult HistoryBook::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);
	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	InputManager()->SetCamera(NULL);
	InputManager()->Register(this);

	GameState()->m_currentArea = LegoGameState::Area::e_histbook;
	GameState()->StopArea(LegoGameState::Area::e_previousArea);
	return result;
}

// FUNCTION: LEGO1 0x10082680
// FUNCTION: BETA10 0x1002b907
MxLong HistoryBook::Notify(MxParam& p_param)
{
	MxNotificationParam& param = (MxNotificationParam&) p_param;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (param.GetNotification()) {
		case c_notificationButtonUp:
			m_destLocation = LegoGameState::Area::e_infoscor;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(m_destLocation);
			break;
		}
	}

	return 0;
}

inline void SetColor(MxStillPresenter* p_presenter, MxU8 p_color, MxU8* p_colors, MxS32 p_x, MxS32 p_y)
{
	if (p_color) {
		for (MxS32 lax = 0; lax < 4; lax++) {
			if (p_presenter->GetAlphaMask() != NULL) {
				memset(NULL, p_colors[p_color - 1], 4);
			}
			else {
				memset(p_presenter->GetBitmap()->GetStart(p_x, p_y + lax), p_colors[p_color - 1], 4);
			}
		}
	}
}

// FUNCTION: LEGO1 0x100826f0
void HistoryBook::ReadyWorld()
{
	LegoWorld::ReadyWorld();
	GameState()->GetHistory()->WriteScoreHistory();

	char bitmap[] = "A_Bitmap";
	for (MxS16 i = 0; i < 26; i++) {
		m_alphabet[i] = (MxStillPresenter*) Find("MxStillPresenter", bitmap);
		bitmap[0]++;
	}

	MxStillPresenter* scoreboxMaster = (MxStillPresenter*) Find("MxStillPresenter", "ScoreBox");
	MxU8 scoreColors[3] =
		{0x76, 0x4c, 0x38}; // yellow - #FFB900, blue - #00548C, red - #CB1220, background - #CECECE, border - #74818B
	MxS32 scoreY = 0x79;

	for (MxS16 scoreIndex = 0; scoreIndex < GameState()->GetHistory()->m_count; scoreIndex++) {
		LegoGameState::ScoreItem* score = GameState()->GetHistory()->GetScore(scoreIndex);

		MxStillPresenter** scorebox = &m_scores[scoreIndex];
		*scorebox = scoreboxMaster->Clone();

		MxS32 scoreX = 0x90;
		if (scoreIndex >= 10) {
			if (scoreIndex == 10) {
				scoreY = 0x79;
			}

			scoreX = 0x158;
		}

		MxS32 scoreboxX = 1;
		MxS32 scoreboxRow = 5;
		MxS32 scoreState = 0;

		for (; scoreboxRow > 0; scoreboxRow--) {
			for (MxS32 scoreBoxColumn = 0, scoreboxY = 1; scoreBoxColumn < 5; scoreBoxColumn++, scoreboxY += 5) {
				SetColor(*scorebox, score->m_scores[scoreState][scoreBoxColumn], scoreColors, scoreboxX, scoreboxY);
			}

			scoreState++;
			scoreboxX += 5;
		}

		(*scorebox)->Enable(TRUE);
		(*scorebox)->SetTickleState(MxPresenter::e_repeating);
		(*scorebox)->SetPosition(scoreX + 0xa1, scoreY);

		for (MxS16 letterIndex = 0; letterIndex < (MxS16) sizeOfArray(m_names[0]);) {
			MxS16 letter = score->m_name.m_letters[letterIndex];

			if (letter == -1) {
				break;
			}

			MxS16 nameIndex = letterIndex++;
			m_names[scoreIndex][nameIndex] = m_alphabet[letter]->Clone();
			m_names[scoreIndex][nameIndex]->Enable(TRUE);
			m_names[scoreIndex][nameIndex]->SetTickleState(MxPresenter::e_repeating);
			m_names[scoreIndex][nameIndex]->SetPosition(scoreX, scoreY);
			scoreX += 0x17;
		}

		scoreY += 0x1b;
	}

	PlayMusic(JukeboxScript::c_InformationCenter_Music);
}

// FUNCTION: LEGO1 0x10082a10
MxBool HistoryBook::Escape()
{
	m_destLocation = LegoGameState::Area::e_infomain;
	return TRUE;
}
