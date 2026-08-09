// Declaration-record carrier (dial campaign): the functions below
// sample this translation unit's accumulated declaration state at this
// point.  Neutral stand-in; no authentic 1997 declaration is
// recoverable here.
class MxUnkRecordSW7000;
class MxUnkRecordSW7001;
class MxUnkRecordSW7002;
class MxUnkRecordSW7003;
class MxUnkRecordSW7004;
class MxUnkRecordSW7005;
class MxUnkRecordSW7006;
class MxUnkRecordSW7007;
class MxUnkRecordSW7008;
class MxUnkRecordSW7009;
class MxUnkRecordSW7010;
class MxUnkRecordSW7011;
class MxUnkRecordSW7012;
class MxUnkRecordSW7013;
class MxUnkRecordSW7014;
class MxUnkRecordSW7015;
class MxUnkRecordSW7016;
class MxUnkRecordSW7017;
class MxUnkRecordSW7018;
class MxUnkRecordSW7019;
class MxUnkRecordSW7020;
class MxUnkRecordSW7021;
class MxUnkRecordSW7022;
class MxUnkRecordSW7023;
class MxUnkRecordSW7024;
class MxUnkRecordSW7025;
class MxUnkRecordSW7026;
class MxUnkRecordSW7027;
class MxUnkRecordSW7028;
class MxUnkRecordSW7029;
class MxUnkRecordSW7030;
class MxUnkRecordSW7031;
class MxUnkRecordSW7032;
class MxUnkRecordSW7033;
class MxUnkRecordSW7034;
class MxUnkRecordSW7035;
class MxUnkRecordSW7036;
class MxUnkRecordSW7037;
class MxUnkRecordSW7038;
class MxUnkRecordSW7039;
class MxUnkRecordSW7040;
class MxUnkRecordSW7041;
class MxUnkRecordSW7042;
class MxUnkRecordSW7043;
class MxUnkRecordSW7044;
class MxUnkRecordSW7045;
class MxUnkRecordSW7046;
class MxUnkRecordSW7047;
class MxUnkRecordSW7048;
class MxUnkRecordSW7049;
class MxUnkRecordSW7050;
class MxUnkRecordSW7051;
class MxUnkRecordSW7052;
class MxUnkRecordSW7053;
class MxUnkRecordSW7054;
class MxUnkRecordSW7055;
class MxUnkRecordSW7056;
class MxUnkRecordSW7057;
class MxUnkRecordSW7058;
class MxUnkRecordSW7059;
class MxUnkRecordSW7060;
class MxUnkRecordSW7061;
class MxUnkRecordSW7062;
class MxUnkRecordSW7063;
class MxUnkRecordSW7064;
class MxUnkRecordSW7065;
class MxUnkRecordSW7066;
class MxUnkRecordSW7067;
class MxUnkRecordSW7068;
class MxUnkRecordSW7069;
class MxUnkRecordSW7070;
class MxUnkRecordSW7071;
class MxUnkRecordSW7072;
class MxUnkRecordSW7073;
class MxUnkRecordSW7074;
class MxUnkRecordSW7075;
class MxUnkRecordSW7076;
class MxUnkRecordSW7077;
class MxUnkRecordSW7078;
class MxUnkRecordSW7079;
class MxUnkRecordSW7080;
class MxUnkRecordSW7081;
class MxUnkRecordSW7082;
class MxUnkRecordSW7083;
class MxUnkRecordSW7084;
class MxUnkRecordSW7085;
class MxUnkRecordSW7086;
class MxUnkRecordSW7087;
class MxUnkRecordSW7088;
class MxUnkRecordSW7089;
class MxUnkRecordSW7090;
class MxUnkRecordSW7091;
class MxUnkRecordSW7092;
class MxUnkRecordSW7093;
class MxUnkRecordSW7094;
class MxUnkRecordSW7095;
class MxUnkRecordSW7096;
class MxUnkRecordSW7097;
class MxUnkRecordSW7098;
class MxUnkRecordSW7099;
class MxUnkRecordSW7100;
class MxUnkRecordSW7101;
class MxUnkRecordSW7102;
class MxUnkRecordSW7103;
class MxUnkRecordSW7104;
class MxUnkRecordSW7105;
class MxUnkRecordSW7106;
class MxUnkRecordSW7107;
class MxUnkRecordSW7108;
class MxUnkRecordSW7109;
class MxUnkRecordSW7110;
class MxUnkRecordSW7111;
class MxUnkRecordSW7112;
class MxUnkRecordSW7113;
class MxUnkRecordSW7114;
class MxUnkRecordSW7115;
class MxUnkRecordSW7116;
class MxUnkRecordSW7117;
class MxUnkRecordSW7118;
class MxUnkRecordSW7119;
class MxUnkRecordSW7120;
class MxUnkRecordSW7121;
class MxUnkRecordSW7122;
class MxUnkRecordSW7123;
class MxUnkRecordSW7124;
class MxUnkRecordSW7125;
class MxUnkRecordSW7126;
class MxUnkRecordSW7127;
class MxUnkRecordSW7128;
class MxUnkRecordSW7129;
class MxUnkRecordSW7130;
class MxUnkRecordSW7131;
class MxUnkRecordSW7132;
class MxUnkRecordSW7133;
class MxUnkRecordSW7134;
class MxUnkRecordSW7135;
class MxUnkRecordSW7136;

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
// FUNCTION: BETA10 0x1002b80f
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

// FUNCTION: LEGO1 0x100826f0
// FUNCTION: BETA10 0x1002b9b9
void HistoryBook::ReadyWorld()
{
	undefined2 dummy1 = 0x90, dummy2 = 0x79, dummy3 = 0xc8, dummy4 = 0x17, dummy5 = 0x1b;
#ifndef BETA10
	LegoWorld::ReadyWorld();
#endif
	GameState()->m_history.WriteScoreHistory();

	char bitmap[] = "A_Bitmap";
	MxS16 i;

	for (i = 0; i < 26; i++) {
		// TODO: This might be an inline function.
		// See also `RegistrationBook::ReadyWorld()`.
		if (i < 26) {
			m_alphabet[i] = (MxStillPresenter*) Find("MxStillPresenter", bitmap);
			assert(m_alphabet[i]);
			bitmap[0]++;
		}
	}

	MxStillPresenter* scoreboxMaster = (MxStillPresenter*) Find("MxStillPresenter", "ScoreBox");
	MxU8 scoreColors[3] =
		{0x76, 0x4c, 0x38}; // yellow - #FFB900, blue - #00548C, red - #CB1220, background - #CECECE, border - #74818B

	MxS32 scoreY;

	for (i = 0, scoreY = 0x79; i < GameState()->m_history.GetCount(); i++, scoreY += 0x1b) {
		LegoGameState::ScoreItem* score = GameState()->m_history.GetScore(i);

		m_scores[i] = scoreboxMaster->Clone();

		MxS32 scoreX = 0x90;
		if (i >= 10) {
			if (i == 10) {
				scoreY = 0x79;
			}

			scoreX = 0x158;
		}

		for (MxS32 scoreState = 0, scoreboxX = 1; scoreState < 5; scoreState++, scoreboxX += 5) {
			MxU8 color;
			for (MxS32 scoreBoxColumn = 0, scoreboxY = 1; scoreBoxColumn < 5; scoreBoxColumn++, scoreboxY += 5) {
				color = score->m_scores[scoreState][scoreBoxColumn];

				if (color > 0) {
					for (MxS32 lax = 0; lax < 4; lax++) {
#ifdef BETA10
						memset(m_scores[i]->GetBitmapStart(scoreboxX, scoreboxY + lax), scoreColors[color - 1], 4);
#else
						if (m_scores[i]->GetAlphaMask() != NULL) {
							memset(NULL, scoreColors[color - 1], 4);
						}
						else {
							memset(
								m_scores[i]->GetBitmap()->GetStart(scoreboxX, lax + scoreboxY),
								scoreColors[color - 1],
								4
							);
						}
#endif
					}
				}
			}
		}

		m_scores[i]->Enable(TRUE);
		m_scores[i]->SetTickleState(MxPresenter::e_repeating);
		m_scores[i]->SetPosition(scoreX + 0xa1, scoreY);

#ifdef BETA10
		for (MxS16 j = 0; score->m_name.m_letters[j] != -1; j++, scoreX += 0x17)
#else
		for (MxS16 j = 0; j < (MxS16) sizeOfArray(m_name[0]) && score->m_name.m_letters[j] != -1; j++, scoreX += 0x17)
#endif
		{
			m_name[i][j] = m_alphabet[score->m_name.m_letters[j]]->Clone();

			assert(m_name[i][j]);
			m_name[i][j]->Enable(TRUE);
			m_name[i][j]->SetTickleState(MxPresenter::e_repeating);
			m_name[i][j]->SetPosition(scoreX, scoreY);
		}
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
