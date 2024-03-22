#include "jukeboxentity.h"

#include "isle.h"
#include "isle_actions.h"
#include "islepathactor.h"
#include "jukebox_actions.h"
#include "jukeboxstate.h"
#include "legogamestate.h"
#include "legoomni.h"
#include "legoutils.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxtransitionmanager.h"

DECOMP_SIZE_ASSERT(JukeBoxEntity, 0x6c)

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

		((Isle*) FindWorld(*g_isleScript, 0))->SetDestLocation(LegoGameState::e_jukeboxw);
		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
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
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz001bd_RunAnim, NULL);
		GameState()->SetUnknown0x41c(JukeboxScript::c_JBMusic1);
		break;
	case 1:
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz006bd_RunAnim, NULL);
		GameState()->SetUnknown0x41c(JukeboxScript::c_JBMusic2);
		break;
	case 2:
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz003bd_RunAnim, NULL);
		GameState()->SetUnknown0x41c(JukeboxScript::c_JBMusic3);
		break;
	case 3:
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz002bd_RunAnim, NULL);
		GameState()->SetUnknown0x41c(JukeboxScript::c_JBMusic4);
		break;
	case 4:
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz007bd_RunAnim, NULL);
		GameState()->SetUnknown0x41c(JukeboxScript::c_JBMusic5);
		break;
	case 5:
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz004bd_RunAnim, NULL);
		GameState()->SetUnknown0x41c(JukeboxScript::c_JBMusic6);
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
void JukeBoxEntity::StopAction(JukeboxScript::Script p_script)
{
	JukeBoxState* state = (JukeBoxState*) GameState()->GetState("JukeBoxState");

	if (state && state->IsActive()) {
		switch (p_script) {
		case JukeboxScript::c_JBMusic1:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz001bd_RunAnim, NULL);
			break;
		case JukeboxScript::c_JBMusic2:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz006bd_RunAnim, NULL);
			break;
		case JukeboxScript::c_JBMusic3:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz003bd_RunAnim, NULL);
			break;
		case JukeboxScript::c_JBMusic4:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz002bd_RunAnim, NULL);
			break;
		case JukeboxScript::c_JBMusic5:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz007bd_RunAnim, NULL);
			break;
		case JukeboxScript::c_JBMusic6:
			state->SetActive(FALSE);
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz004bd_RunAnim, NULL);
			break;
		}

		BackgroundAudioManager()->Enable(IsBackgroundAudioEnabled());
	}
}
