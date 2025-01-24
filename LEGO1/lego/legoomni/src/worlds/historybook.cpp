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
	memset(m_name, 0, sizeof(m_name));
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

		for (MxS16 letterIndex = 0; letterIndex < (MxS16) sizeOfArray(m_name[0]); letterIndex++) {
			if (m_name[scoreIndex][letterIndex]) {
				delete m_name[scoreIndex][letterIndex]->GetAction();
				delete m_name[scoreIndex][letterIndex];
				m_name[scoreIndex][letterIndex] = NULL;
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
// FUNCTION: BETA10 0x1002b9b9
void HistoryBook::ReadyWorld()
{
	undefined4 dummy1;

	LegoWorld::ReadyWorld();
	GameState()->m_history.WriteScoreHistory();

	char bitmap[] = "A_Bitmap";
	MxS16 i = 0;

	for (; i < 26; i++) {
		m_alphabet[i] = (MxStillPresenter*) Find("MxStillPresenter", bitmap);
		assert(m_alphabet[i]);
		bitmap[0]++;
	}

	MxStillPresenter* scoreboxMaster = (MxStillPresenter*) Find("MxStillPresenter", "ScoreBox");
	MxU8 scoreColors[3] =
		{0x76, 0x4c, 0x38}; // yellow - #FFB900, blue - #00548C, red - #CB1220, background - #CECECE, border - #74818B
	MxS32 scoreY = 0x79;

	for (i = 0; i < GameState()->m_history.GetCount(); i++) {
		LegoGameState::ScoreItem* score = GameState()->m_history.GetScore(i);

		MxStillPresenter** scorebox = &m_scores[i];
		*scorebox = scoreboxMaster->Clone();

		MxS32 scoreX = 0x90;
		if (i >= 10) {
			if (i == 10) {
				scoreY = 0x79;
			}

			scoreX = 0x158;
		}

		MxS32 scoreboxX = 1;
		MxS32 scoreboxRow = 5;

		for (MxS32 scoreState = 0; scoreState < 5; scoreState++) {
			for (MxS32 scoreBoxColumn = 0, scoreboxY = 1; scoreBoxColumn < 5; scoreBoxColumn++, scoreboxY += 5) {
				// SetColor(*scorebox, score->m_scores[scoreState][scoreBoxColumn], scoreColors, scoreboxX, scoreboxY);
				// inline void SetColor(MxStillPresenter* p_presenter, MxU8 p_color, MxU8* p_colors, MxS32 p_x, MxS32 p_y)
				MxU8 color = score->m_scores[scoreState][scoreBoxColumn];
				// this->m_scores
				if (color) {
					for (MxS32 lax = 0; lax < 4; lax++) {
#ifdef BETA10
						memset(m_scores[i]->GetBitmapStart(scoreboxX, scoreboxY + lax), scoreColors[color - 1], 4);
#else
						if ((*scorebox)->GetAlphaMask() != NULL) {
							memset(NULL, scoreColors[color - 1], 4);
						}
						else {
							memset(m_scores[i]->GetBitmap()->GetStart(scoreboxX, scoreboxY + lax), scoreColors[color - 1], 4);
						}
#endif
					}
				}
			}

			scoreState++;
			scoreboxX += 5;
		}

		(*scorebox)->Enable(TRUE);
		(*scorebox)->SetTickleState(MxPresenter::e_repeating);
		(*scorebox)->SetPosition(scoreX + 0xa1, scoreY);

		for (MxS16 letterIndex = 0; letterIndex < (MxS16) sizeOfArray(m_name[0]);) {
			MxS16 letter = score->m_name.m_letters[letterIndex];

			if (letter == -1) {
				break;
			}

			MxS16 j = letterIndex++;

			m_name[i][j] = m_alphabet[letter]->Clone();

			assert(m_name[i][j]);
			m_name[i][j]->Enable(TRUE);
			m_name[i][j]->SetTickleState(MxPresenter::e_repeating);
			m_name[i][j]->SetPosition(scoreX, scoreY);
			scoreX += 0x17;
		}

		scoreY += 0x1b;
	}

#ifndef BETA10
	PlayMusic(JukeboxScript::c_InformationCenter_Music);
#endif
}

// FUNCTION: LEGO1 0x10082a10
MxBool HistoryBook::Escape()
{
	m_destLocation = LegoGameState::Area::e_infomain;
	return TRUE;
}
