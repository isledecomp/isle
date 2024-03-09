#include "jukeboxentity.h"

#include "isle.h"
#include "islepathactor.h"
#include "jukeboxstate.h"
#include "legogamestate.h"
#include "legoomni.h"
#include "legoutils.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxtransitionmanager.h"

// FUNCTION: LEGO1 0x10085bc0
JukeBoxEntity::JukeBoxEntity()
{
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10085dd0
JukeBoxEntity::~JukeBoxEntity()
{
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10085e40
MxLong JukeBoxEntity::Notify(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetType() == c_notificationType11) {
		if (!FUN_1003ef60()) {
			return 1;
		}

		if (CurrentActor()->GetActorId() != GameState()->GetActorId()) {
			CurrentActor()->VTable0xe4();
		}

		((Isle*) FindWorld(*g_isleScript, 0))->SetUnknown13c(0x35);
		TransitionManager()->StartTransition(MxTransitionManager::e_pixelation, 50, FALSE, FALSE);
		return 1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x10085ed0
void JukeBoxEntity::StartAction()
{
	MxDSAction action;
	BackgroundAudioManager()->Stop();
	JukeBoxState* state = (JukeBoxState*) GameState()->GetState("JukeBoxState");
	state->SetActive(TRUE);

	switch (state->GetState()) {
	case 0:
		InvokeAction(Extra::e_start, *g_isleScript, 0x319, NULL);
		GameState()->SetUnknown0x41c(0x37);
		break;
	case 1:
		InvokeAction(Extra::e_start, *g_isleScript, 0x31e, NULL);
		GameState()->SetUnknown0x41c(0x38);
		break;
	case 2:
		InvokeAction(Extra::e_start, *g_isleScript, 0x31b, NULL);
		GameState()->SetUnknown0x41c(0x39);
		break;
	case 3:
		InvokeAction(Extra::e_start, *g_isleScript, 0x31a, NULL);
		GameState()->SetUnknown0x41c(0x3a);
		break;
	case 4:
		InvokeAction(Extra::e_start, *g_isleScript, 0x31f, NULL);
		GameState()->SetUnknown0x41c(0x3b);
		break;
	case 5:
		InvokeAction(Extra::e_start, *g_isleScript, 0x31c, NULL);
		GameState()->SetUnknown0x41c(0x3c);
		break;
	}

	action.SetAtomId(*g_jukeboxScript);
	action.SetObjectId(GameState()->GetUnknown0x41c());

	m_audioEnabled = BackgroundAudioManager()->GetEnabled();
	if (!m_audioEnabled) {
		BackgroundAudioManager()->Enable(TRUE);
	}

	BackgroundAudioManager()->PlayMusic(action, 5, 4);
}

// FUNCTION: LEGO1 0x100860f0
void JukeBoxEntity::StopAction(MxU32 p_state)
{
	JukeBoxState* state = (JukeBoxState*) GameState()->GetState("JukeBoxState");

	if (state && state->IsActive()) {
		switch (p_state) {
		case 0x37:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, 0x319, NULL);
			break;
		case 0x38:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, 0x31e, NULL);
			break;
		case 0x39:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, 0x31b, NULL);
			break;
		case 0x3a:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, 0x31a, NULL);
			break;
		case 0x3b:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, 0x31f, NULL);
			break;
		case 0x3c:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, 0x31c, NULL);
			break;
		}

		BackgroundAudioManager()->Enable(IsBackgroundAudioEnabled());
	}
}
