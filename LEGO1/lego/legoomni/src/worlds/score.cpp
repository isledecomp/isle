// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordWL;
class MxUnkRecordWM;
class MxUnkRecordWN;
class MxUnkRecordWS000;
class MxUnkRecordWS001;
class MxUnkRecordWS002;
class MxUnkRecordWS003;
class MxUnkRecordWS004;
class MxUnkRecordWS005;
class MxUnkRecordWS006;
class MxUnkRecordWS007;
class MxUnkRecordWS008;
class MxUnkRecordWS009;

#include "score.h"

#include "ambulance.h"
#include "carrace.h"
#include "infoscor_actions.h"
#include "jetski.h"
#include "jetskirace.h"
#include "jukebox.h"
#include "jukebox_actions.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legomain.h"
#include "misc.h"
#include "misc/legocontainer.h"
#include "mxactionnotificationparam.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxnotificationparam.h"
#include "mxtransitionmanager.h"
#include "pizza.h"
#include "scripts.h"
#include "towtrack.h"

// Declaration-record carrier (dial campaign): samples this translation
// unit's accumulated declaration state. Neutral stand-in.  [6 units]
enum RkScE0 {
	c_rkScE0
};
enum RkScE1 {
	c_rkScE1
};
enum RkScE2 {
	c_rkScE2
};

DECOMP_SIZE_ASSERT(Score, 0x104)
DECOMP_SIZE_ASSERT(ScoreState, 0x0c)

// FUNCTION: LEGO1 0x10001000
Score::Score()
{
	m_destLocation = LegoGameState::e_undefined;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10001200
Score::~Score()
{
	if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}

	InputManager()->UnRegister(this);
	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x100012a0
MxResult Score::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoWorld::Create(p_dsAction);

	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
		InputManager()->Register(this);
		SetIsWorldActive(FALSE);
		LegoGameState* gameState = GameState();
		ScoreState* state = (ScoreState*) gameState->GetState("ScoreState");
		m_state = state ? state : (ScoreState*) gameState->CreateState("ScoreState");
		GameState()->m_currentArea = LegoGameState::e_infoscor;
		GameState()->StopArea(LegoGameState::e_previousArea);
	}

	return result;
}

// FUNCTION: LEGO1 0x10001340
void Score::DeleteScript()
{
	if (m_state->GetTutorialFlag()) {
		MxDSAction action;
		action.SetObjectId(InfoscorScript::c_iicc31in_PlayWav);
		action.SetAtomId(*g_infoscorScript);
		action.SetUnknown24(-2);
		DeleteObject(action);
		m_state->SetTutorialFlag(FALSE);
	}
}

// FUNCTION: LEGO1 0x10001410
// FUNCTION: BETA10 0x100f4398
MxLong Score::Notify(MxParam& p_param)
{
	MxLong ret = 0;
	MxNotificationParam& param = (MxNotificationParam&) p_param;

	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (param.GetNotification()) {
		case c_notificationStartAction:
			Paint();
			ret = 1;
			break;
		case c_notificationEndAction:
			ret = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationKeyPress:
			if (((LegoEventNotificationParam&) p_param).GetKey() == VK_SPACE) {
				DeleteScript();
			}
			ret = 1;
			break;
		case c_notificationControl:
			ret = HandleControl((LegoControlManagerNotificationParam&) p_param);
			break;
		case c_notificationTransitioned:
			DeleteObjects(g_infoscorScript, InfoscorScript::c_LegoBox1_Flc, InfoscorScript::c_LegoBox3_Flc);
			if (m_destLocation) {
				GameState()->SwitchArea(m_destLocation);
			}
			ret = 1;
			break;
		}
	}

	return ret;
}

// FUNCTION: LEGO1 0x10001510
MxLong Score::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	MxDSAction* action = p_param.GetAction();

	if (m_atomId == action->GetAtomId()) {
		switch (action->GetObjectId()) {
		case InfoscorScript::c_GoTo_HistBook:
			m_destLocation = LegoGameState::e_histbook;
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case InfoscorScript::c_iicc31in_PlayWav:
			PlayMusic(JukeboxScript::c_InformationCenter_Music);
			m_state->SetTutorialFlag(FALSE);
			break;
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x10001580
void Score::ReadyWorld()
{
	LegoWorld::ReadyWorld();

	MxDSAction action;
	action.SetObjectId(InfoscorScript::c_nin001pr_RunAnim);
	action.SetAtomId(m_atomId);
	action.SetNotificationObject(this);
	Start(&action);

	if (m_state->GetTutorialFlag()) {
		MxDSAction action;
		action.SetObjectId(InfoscorScript::c_iicc31in_PlayWav);
		action.SetAtomId(*g_infoscorScript);
		Start(&action);
	}
	else {
		PlayMusic(JukeboxScript::c_InformationCenter_Music);
	}

	Disable(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// Declaration-record carrier: a SECOND seat is required here. The unit's
// head carrier fixes the map _Lbound it supplies, but doing so moves
// Score::FillArea and Score::Paint; only a carrier seated at this point
// reaches those two without disturbing _Lbound again. Neutral stand-in
// pending recovery of the 1997 declaration text.
class MxUnkRecordWT000;
class MxUnkRecordWT001;
class MxUnkRecordWT002;
class MxUnkRecordWT003;
class MxUnkRecordWT004;
class MxUnkRecordWT005;
class MxUnkRecordWT006;
class MxUnkRecordWT007;
class MxUnkRecordWT008;
class MxUnkRecordWT009;
class MxUnkRecordWT010;
class MxUnkRecordWT011;
class MxUnkRecordWT012;
class MxUnkRecordWT013;
class MxUnkRecordWT014;
class MxUnkRecordWT015;
class MxUnkRecordWT016;
class MxUnkRecordWT017;
class MxUnkRecordWT018;
class MxUnkRecordWT019;
class MxUnkRecordWT020;
class MxUnkRecordWT021;
class MxUnkRecordWT022;

// FUNCTION: LEGO1 0x100016d0
MxLong Score::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	MxS16 enabledChild = p_param.m_enabledChild;

	if (enabledChild == 1 || p_param.m_clickedObjectId == InfoscorScript::c_LegoBox_Ctl) {
		switch (p_param.m_clickedObjectId) {
		case InfoscorScript::c_LeftArrow_Ctl:
			m_destLocation = LegoGameState::e_infomain;
			DeleteScript();
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case InfoscorScript::c_RightArrow_Ctl:
			m_destLocation = LegoGameState::e_infodoor;
			DeleteScript();
			TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
			break;
		case InfoscorScript::c_Book_Ctl: {
			InputManager()->DisableInputProcessing();
			DeleteScript();

			MxDSAction action;
			action.SetObjectId(InfoscorScript::c_GoTo_HistBook);
			action.SetAtomId(*g_infoscorScript);
			Start(&action);
			break;
		}
		case InfoscorScript::c_LegoBox_Ctl: {
			switch (enabledChild) {
			case 1: {
				MxDSAction action;
				action.SetObjectId(InfoscorScript::c_LegoBox1_Flc);
				action.SetAtomId(*g_infoscorScript);
				Start(&action);
				break;
			}
			case 2: {
				MxDSAction action;
				action.SetObjectId(InfoscorScript::c_LegoBox2_Flc);
				action.SetAtomId(*g_infoscorScript);
				Start(&action);
				break;
			}
			case 3: {
				MxDSAction action;
				action.SetObjectId(InfoscorScript::c_LegoBox3_Flc);
				action.SetAtomId(*g_infoscorScript);
				Start(&action);
				break;
			}
			}
			break;
		}
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x10001980
void Score::Enable(MxBool p_enable)
{
	LegoWorld::Enable(p_enable);

	if (p_enable) {
		InputManager()->SetWorld(this);
		SetIsWorldActive(FALSE);
	}
	else if (InputManager()->GetWorld() == this) {
		InputManager()->ClearWorld();
	}
}

// FUNCTION: LEGO1 0x100019d0
// FUNCTION: BETA10 0x100f47d8
void Score::Paint()
{
	LegoTextureInfo* cube = TextureContainer()->Get("bigcube.gif");

	if (cube != NULL) {
		JetskiRaceState* jetskiRaceState = (JetskiRaceState*) GameState()->GetState("JetskiRaceState");
		CarRaceState* carRaceState = (CarRaceState*) GameState()->GetState("CarRaceState");
		TowTrackMissionState* towTrackMissionState =
			(TowTrackMissionState*) GameState()->GetState("TowTrackMissionState");
		PizzaMissionState* pizzaMissionState = (PizzaMissionState*) GameState()->GetState("PizzaMissionState");
		AmbulanceMissionState* ambulanceMissionState =
			(AmbulanceMissionState*) GameState()->GetState("AmbulanceMissionState");

		DDSURFACEDESC desc;
		memset(&desc, 0, sizeof(desc));
		desc.dwSize = sizeof(desc);

		HRESULT result = cube->m_surface->Lock(NULL, &desc, DDLOCK_SURFACEMEMORYPTR, NULL);
		if (result == DD_OK) {
			if (desc.lPitch != desc.dwWidth) {
				cube->m_surface->Unlock(desc.lpSurface);
				return;
			}

			m_surface = (MxU8*) desc.lpSurface;

			for (MxU8 actor = 1; actor <= 5; actor++) {
				MxS16 score;

				score = carRaceState ? carRaceState->GetState(actor)->GetHighScore() : 0;
				FillArea(0, actor - 1, score);

				score = jetskiRaceState ? jetskiRaceState->GetState(actor)->GetHighScore() : 0;
				FillArea(1, actor - 1, score);

				score = pizzaMissionState ? pizzaMissionState->GetHighScore(actor) : 0;
				FillArea(2, actor - 1, score);

				score = towTrackMissionState ? towTrackMissionState->GetHighScore(actor) : 0;
				FillArea(3, actor - 1, score);

				score = ambulanceMissionState ? ambulanceMissionState->GetHighScore(actor) : 0;
				FillArea(4, actor - 1, score);
			}

			cube->m_surface->Unlock(desc.lpSurface);
			cube->m_texture->Changed(TRUE, FALSE);
			m_surface = NULL;
		}
	}
}

// FUNCTION: LEGO1 0x10001d20
// FUNCTION: BETA10 0x100f4a52
void Score::FillArea(MxS32 i_activity, MxS32 i_actor, MxS16 score)
{
	MxS32 areaYOffsets[] = {0x2b00, 0x5700, 0x8000, 0xab00, 0xd600};
	MxS32 areaHeights[] = {0x2a, 0x27, 0x29, 0x29, 0x2a};
	MxS32 areaXOffsets[] = {0x2f, 0x56, 0x81, 0xaa, 0xd4};
	MxS32 areaWidths[] = {0x25, 0x29, 0x27, 0x28, 0x28};
	MxS32 colors[] = {0x11, 0x0f, 0x08, 0x05};

	assert(i_activity >= 0 && i_activity < 5);
	assert(i_actor >= 0 && i_actor < 5);
	assert(score >= 0 && score < 4);

	MxU8* ptr = m_surface + areaYOffsets[i_actor] + areaXOffsets[i_activity];
	MxS32 color = colors[score];
	MxS32 size = areaWidths[i_activity];

	for (MxS32 i = 0; i < areaHeights[i_actor]; i++) {
		memset(ptr, color, size);
		ptr += 0x100;
	}
}

// FUNCTION: LEGO1 0x10001e40
MxBool Score::Escape()
{
	DeleteScript();
	m_destLocation = LegoGameState::e_infomain;
	return TRUE;
}
