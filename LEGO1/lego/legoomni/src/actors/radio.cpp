#include "radio.h"

#include "isle_actions.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoomni.h"
#include "misc.h"
#include "mxbackgroundaudiomanager.h"
#include "mxcontrolpresenter.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(Radio, 0x10)

// FUNCTION: LEGO1 0x1002c850
Radio::Radio()
{
	NotificationManager()->Register(this);
	ControlManager()->Register(this);

	m_unk0x0c = TRUE;
	CreateRadioState();
}

// FUNCTION: LEGO1 0x1002c990
Radio::~Radio()
{
	if (m_state->IsActive()) {
		BackgroundAudioManager()->Stop();
		m_state->SetActive(FALSE);
	}

	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x1002ca30
MxLong Radio::Notify(MxParam& p_param)
{
	MxLong result = 0;

	if (m_unk0x0c) {
		switch (((MxNotificationParam&) p_param).GetType()) {
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationClick:
			result = HandleClick((LegoControlManagerEvent&) p_param);
			break;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1002ca70
void Radio::Play()
{
	if (!m_state->IsActive()) {
		CurrentWorld();

		MxDSAction action;
		action.SetObjectId(m_state->FUN_1002d090());
		action.SetAtomId(*g_jukeboxScript);
		action.SetLoopCount(1);

		m_audioEnabled = BackgroundAudioManager()->GetEnabled();
		if (!m_audioEnabled) {
			BackgroundAudioManager()->Enable(TRUE);
		}

		BackgroundAudioManager()->PlayMusic(action, 3, 4);
		m_state->SetActive(TRUE);
	}
}

// FUNCTION: LEGO1 0x1002cb70
void Radio::Stop()
{
	if (m_state->IsActive()) {
		LegoWorld* world = CurrentWorld();

		MxControlPresenter* presenter = (MxControlPresenter*) world->Find(world->GetAtom(), 18);

		if (presenter) {
			presenter->VTable0x6c(0);
		}

		BackgroundAudioManager()->Stop();
		BackgroundAudioManager()->Enable(m_audioEnabled);
		m_state->SetActive(FALSE);
	}
}

// FUNCTION: LEGO1 0x1002cbc0
MxLong Radio::HandleClick(LegoControlManagerEvent& p_param)
{
	MxDSAction action; // Unused
	MxS32 objectId = p_param.GetClickedObjectId();

	if (objectId == IsleScript::c_Radio_Ctl) {
		if (m_state->IsActive()) {
			Stop();
		}
		else {
			Play();
		}

		if (CurrentWorld()) {
#ifdef COMPAT_MODE
			MxNotificationParam param(c_notificationEndAction, this);
			CurrentWorld()->Notify(param);
#else
			CurrentWorld()->Notify(MxNotificationParam(c_notificationType0, this));
#endif
		}

		return 1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1002ccc0
MxLong Radio::HandleEndAction(MxEndActionNotificationParam& p_param)
{
	if (m_state->IsActive() &&
		m_state->FUN_1002d0c0(p_param.GetAction()->GetAtomId(), p_param.GetAction()->GetObjectId())) {

		MxDSAction action;
		action.SetAtomId(*g_jukeboxScript);
		action.SetObjectId(m_state->FUN_1002d090());
		action.SetLoopCount(1);

		BackgroundAudioManager()->PlayMusic(action, 3, 4);
		return 1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1002cdc0
void Radio::Initialize(MxBool p_und)
{
	if (m_unk0x0c != p_und) {
		m_unk0x0c = p_und;
		CreateRadioState();
	}
}

// FUNCTION: LEGO1 0x1002cde0
void Radio::CreateRadioState()
{
	LegoGameState* gameState = GameState();
	RadioState* state = (RadioState*) gameState->GetState("RadioState");
	if (state == NULL) {
		state = (RadioState*) gameState->CreateState("RadioState");
	}

	m_state = state;
}
