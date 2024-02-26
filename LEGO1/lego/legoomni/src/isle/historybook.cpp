#include "historybook.h"

#include "jukebox.h"
#include "legocontrolmanager.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"
#include "mxomni.h"
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(HistoryBook, 0x3e4)

// FUNCTION: LEGO1 0x100822f0
HistoryBook::HistoryBook()
{
	memset(m_alphabet, NULL, sizeof(m_alphabet));
	memset(m_names, NULL, sizeof(m_names));
	memset(m_scores, NULL, sizeof(m_scores));
	NotificationManager()->Register(this);
}

// STUB: LEGO1 0x100824d0
HistoryBook::~HistoryBook()
{
	// TODO
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

	GameState()->SetCurrentArea(LegoGameState::Area::e_histbook);
	GameState()->StopArea(LegoGameState::Area::e_previousArea);
	return result;
}

// FUNCTION: LEGO1 0x10082680
MxLong HistoryBook::Notify(MxParam& p_param)
{
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetNotification()) {
		case c_notificationButtonUp:
			m_transitionDestination = LegoGameState::Area::e_infoscor;
			TransitionManager()->StartTransition(MxTransitionManager::TransitionType::e_pixelation, 50, FALSE, FALSE);
			break;
		case c_notificationTransitioned:
			GameState()->SwitchArea(m_transitionDestination);
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
				SetColor(*scorebox, score->m_state[scoreState][scoreBoxColumn], scoreColors, scoreboxX, scoreboxY);
			}

			scoreState++;
			scoreboxX += 5;
		}

		(*scorebox)->Enable(TRUE);
		(*scorebox)->SetTickleState(MxPresenter::e_repeating);
		(*scorebox)->SetPosition(scoreX + 0xa1, scoreY);

		for (MxS16 letterIndex = 0; letterIndex < (MxS16) _countof(m_names[0]);) {
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

	PlayMusic(JukeBox::e_informationCenter);
}

// FUNCTION: LEGO1 0x10082a10
MxBool HistoryBook::VTable0x64()
{
	m_transitionDestination = LegoGameState::Area::e_infomain;
	return TRUE;
}
