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

DECOMP_SIZE_ASSERT(Score, 0x104)
DECOMP_SIZE_ASSERT(ScoreState, 0x0c)

// FUNCTION: LEGO1 0x10001000
Score::Score()
{
	m_destLocation = LegoGameState::e_undefined;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x100010b0
MxBool Score::VTable0x5c()
{
	return TRUE;
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
		GameState()->SetCurrentArea(LegoGameState::e_infoscor);
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
MxLong Score::Notify(MxParam& p_param)
{
	MxLong ret = 0;
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {
		switch (((MxNotificationParam&) p_param).GetNotification()) {
		case c_notificationStartAction:
			Paint();
			ret = 1;
			break;
		case c_notificationEndAction:
			ret = FUN_10001510((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationKeyPress:
			if (((LegoEventNotificationParam&) p_param).GetKey() == VK_SPACE) {
				DeleteScript();
			}
			ret = 1;
			break;
		case c_notificationControl:
			ret = FUN_100016d0((LegoControlManagerEvent&) p_param);
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
MxLong Score::FUN_10001510(MxEndActionNotificationParam& p_param)
{
	MxDSAction* action = p_param.GetAction();

	if (m_atom == action->GetAtomId()) {
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
	action.SetAtomId(m_atom);
	action.SetUnknown84(this);
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

	FUN_10015820(FALSE, LegoOmni::c_disableInput | LegoOmni::c_disable3d | LegoOmni::c_clearScreen);
}

// FUNCTION: LEGO1 0x100016d0
MxLong Score::FUN_100016d0(LegoControlManagerEvent& p_param)
{
	MxS16 unk0x28 = p_param.GetUnknown0x28();

	if (unk0x28 == 1 || p_param.GetClickedObjectId() == InfoscorScript::c_LegoBox_Ctl) {
		switch (p_param.GetClickedObjectId()) {
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
			switch (unk0x28) {
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

		if (cube->m_surface->Lock(NULL, &desc, 0, NULL) == DD_OK) {
			if (desc.lPitch != desc.dwWidth) {
				cube->m_surface->Unlock(desc.lpSurface);
				return;
			}

			m_surface = (MxU8*) desc.lpSurface;

			for (MxU8 actor = 1; actor <= 5; actor++) {
				MxU16 score;

				score = carRaceState ? carRaceState->GetState(actor)->GetScore() : 0;
				FillArea(0, actor - 1, score);

				score = jetskiRaceState ? jetskiRaceState->GetState(actor)->GetScore() : 0;
				FillArea(1, actor - 1, score);

				score = pizzaMissionState ? pizzaMissionState->GetScore(actor) : 0;
				FillArea(2, actor - 1, score);

				score = towTrackMissionState ? towTrackMissionState->GetScore(actor) : 0;
				FillArea(3, actor - 1, score);

				score = ambulanceMissionState ? ambulanceMissionState->GetScore(actor) : 0;
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
void Score::FillArea(MxU32 i_activity, MxU32 i_actor, MxS16 score)
{
	MxS32 local3c[] = {0x2b00, 0x5700, 0x8000, 0xab00, 0xd600};
	MxS32 local14[] = {0x2a, 0x27, 0x29, 0x29, 0x2a};
	MxS32 local50[] = {0x2f, 0x56, 0x81, 0xaa, 0xd4};
	MxS32 local28[] = {0x25, 0x29, 0x27, 0x28, 0x28};
	MxS32 local60[] = {0x11, 0x0f, 0x08, 0x05};

	MxU8* ptr = m_surface + local3c[i_actor] + local50[i_activity];
	MxS32 val = local60[score];
	MxS32 size = local28[i_activity];

	for (MxS32 i = 0; i < local14[i_actor]; i++) {
		memset(ptr, val, size);
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
