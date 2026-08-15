#include "jukeboxentity.h"

#include "isle.h"
#include "isle_actions.h"
#include "islepathactor.h"
#include "jukebox.h"
#include "jukebox_actions.h"
#include "legogamestate.h"
#include "legoutils.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxnotificationparam.h"
#include "mxtransitionmanager.h"
#include "scripts.h"

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
// FUNCTION: BETA10 0x10038c37
MxLong JukeBoxEntity::Notify(MxParam& p_param)
{
	MxNotificationParam& param = (MxNotificationParam&) p_param;

	if (param.GetNotification() == c_notificationClick) {
		if (!CanExit()) {
			return 1;
		}

		if (UserActor()->GetActorId() != GameState()->GetActorId()) {
			((IslePathActor*) UserActor())->Exit();
		}

		((Isle*) FindWorld(*g_isleScript, IsleScript::c__Isle))->SetDestLocation(LegoGameState::e_jukeboxw);
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
	state->m_active = TRUE;

	switch (state->m_music) {
	case JukeBoxState::e_pasquell:
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz001bd_RunAnim, NULL);
		GameState()->m_jukeboxMusic = JukeboxScript::c_JBMusic1;
		break;
	case JukeBoxState::e_right:
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz006bd_RunAnim, NULL);
		GameState()->m_jukeboxMusic = JukeboxScript::c_JBMusic2;
		break;
	case JukeBoxState::e_decal:
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz003bd_RunAnim, NULL);
		GameState()->m_jukeboxMusic = JukeboxScript::c_JBMusic3;
		break;
	case JukeBoxState::e_wallis:
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz002bd_RunAnim, NULL);
		GameState()->m_jukeboxMusic = JukeboxScript::c_JBMusic4;
		break;
	case JukeBoxState::e_nelson:
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz007bd_RunAnim, NULL);
		GameState()->m_jukeboxMusic = JukeboxScript::c_JBMusic5;
		break;
	case JukeBoxState::e_torpedos:
		InvokeAction(Extra::e_start, *g_isleScript, IsleScript::c_npz004bd_RunAnim, NULL);
		GameState()->m_jukeboxMusic = JukeboxScript::c_JBMusic6;
		break;
	}

	action.SetAtomId(*g_jukeboxScript);
	action.SetObjectId(GameState()->m_jukeboxMusic);

	m_audioEnabled = BackgroundAudioManager()->GetEnabled();
	if (!m_audioEnabled) {
		BackgroundAudioManager()->Enable(TRUE);
	}

	BackgroundAudioManager()->PlayMusic(action, 5, MxPresenter::e_repeating);
}

// FUNCTION: LEGO1 0x100860f0
void JukeBoxEntity::StopAction(JukeboxScript::Script p_script)
{
	JukeBoxState* state = (JukeBoxState*) GameState()->GetState("JukeBoxState");

	if (state && state->m_active) {
		switch (p_script) {
		case JukeboxScript::c_JBMusic1:
			state->m_active = FALSE;
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz001bd_RunAnim, NULL);
			break;
		case JukeboxScript::c_JBMusic2:
			state->m_active = FALSE;
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz006bd_RunAnim, NULL);
			break;
		case JukeboxScript::c_JBMusic3:
			state->m_active = FALSE;
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz003bd_RunAnim, NULL);
			break;
		case JukeboxScript::c_JBMusic4:
			state->m_active = FALSE;
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz002bd_RunAnim, NULL);
			break;
		case JukeboxScript::c_JBMusic5:
			state->m_active = FALSE;
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz007bd_RunAnim, NULL);
			break;
		case JukeboxScript::c_JBMusic6:
			state->m_active = FALSE;
			InvokeAction(Extra::e_stop, *g_isleScript, IsleScript::c_npz004bd_RunAnim, NULL);
			break;
		}

		BackgroundAudioManager()->Enable(IsBackgroundAudioEnabled());
	}
}
