#include "radio.h"

#include "isle_actions.h"
#include "jukebox_actions.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoworld.h"
#include "misc.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxcontrolpresenter.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxtimer.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(Radio, 0x10)
DECOMP_SIZE_ASSERT(RadioState, 0x30)

// GLOBAL: LEGO1 0x100f3218
JukeboxScript::Script g_jingles[] = {
	JukeboxScript::c_sns002ra_Audio,
	JukeboxScript::c_sns001ja_Audio,
	JukeboxScript::c_snsc01js_Audio,
	JukeboxScript::c_snsb01js_Audio,
	JukeboxScript::c_snsa01js_Audio,
	JukeboxScript::c_sns009ra_Audio
};

// GLOBAL: LEGO1 0x100f3230
JukeboxScript::Script g_news[] = {
	JukeboxScript::c_ham035ra_Audio,
	JukeboxScript::c_ham039ra_Audio,
	JukeboxScript::c_sns005ra_Audio,
	JukeboxScript::c_sns078pa_Audio,
	JukeboxScript::c_ham036ra_Audio,
	JukeboxScript::c_sns006ra_Audio,
	JukeboxScript::c_sns013ra_Audio,
	JukeboxScript::c_sns004ra_Audio,
	JukeboxScript::c_sns079pa_Audio,
	JukeboxScript::c_sns007ra_Audio,
	JukeboxScript::c_sns008ra_Audio,
	JukeboxScript::c_hpz037ma_Audio,
	JukeboxScript::c_sns003ra_Audio,
	JukeboxScript::c_sns010ra_Audio,
};

// GLOBAL: LEGO1 0x100f3268
JukeboxScript::Script g_songs[] = {
	JukeboxScript::c_CentralRoads_Music,
	JukeboxScript::c_BeachBlvd_Music,
	JukeboxScript::c_ResidentalArea_Music,
	JukeboxScript::c_Radio1_Music,
	JukeboxScript::c_Radio2_Music,
	JukeboxScript::c_Radio3_Music,
	JukeboxScript::c_Radio4_Music,
	JukeboxScript::c_Radio5_Music,
	JukeboxScript::c_Radio6_Music,
};

// FUNCTION: LEGO1 0x1002c850
Radio::Radio()
{
	NotificationManager()->Register(this);
	ControlManager()->Register(this);

	m_enabled = TRUE;
	CreateState();
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
// FUNCTION: BETA10 0x100f19e8
MxLong Radio::Notify(MxParam& p_param)
{
	MxLong result = 0;

	if (m_enabled) {
		MxNotificationParam& param = (MxNotificationParam&) p_param;
		switch (param.GetNotification()) {
		case c_notificationEndAction:
			result = HandleEndAction((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationControl:
			result = HandleControl((LegoControlManagerNotificationParam&) p_param);
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
		action.SetObjectId(m_state->NextPlaylistObjectId());
		action.SetAtomId(*g_jukeboxScript);
		action.SetLoopCount(1);

		m_audioEnabled = BackgroundAudioManager()->GetEnabled();
		if (!m_audioEnabled) {
			BackgroundAudioManager()->Enable(TRUE);
		}

		BackgroundAudioManager()->PlayMusic(action, 3, MxPresenter::e_repeating);
		m_state->SetActive(TRUE);
	}
}

// FUNCTION: LEGO1 0x1002cb70
void Radio::Stop()
{
	if (m_state->IsActive()) {
		LegoWorld* world = CurrentWorld();

		MxControlPresenter* presenter = (MxControlPresenter*) world->Find(world->GetAtomId(), IsleScript::c_Radio_Ctl);

		if (presenter) {
			presenter->UpdateEnabledChild(0);
		}

		BackgroundAudioManager()->Stop();
		BackgroundAudioManager()->Enable(m_audioEnabled);
		m_state->SetActive(FALSE);
	}
}

// FUNCTION: LEGO1 0x1002cbc0
// FUNCTION: BETA10 0x100f1ce1
MxLong Radio::HandleControl(LegoControlManagerNotificationParam& p_param)
{
	MxDSAction action; // Unused

	switch (p_param.m_clickedObjectId) {
	case IsleScript::c_Radio_Ctl:
		if (m_state->IsActive()) {
			Stop();
		}
		else {
			Play();
		}

		if (CurrentWorld()) {
#ifdef COMPAT_MODE
			MxNotificationParam param(c_notificationType0, this);
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
		m_state->IsRadioObjectId(p_param.GetAction()->GetAtomId(), p_param.GetAction()->GetObjectId())) {

		MxDSAction action;
		action.SetAtomId(*g_jukeboxScript);
		action.SetObjectId(m_state->NextPlaylistObjectId());
		action.SetLoopCount(1);

		BackgroundAudioManager()->PlayMusic(action, 3, MxPresenter::e_repeating);
		return 1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1002cdc0
void Radio::Initialize(MxBool p_und)
{
	if (m_enabled != p_und) {
		m_enabled = p_und;
		CreateState();
	}
}

// FUNCTION: LEGO1 0x1002cde0
void Radio::CreateState()
{
	LegoGameState* gameState = GameState();
	RadioState* state = (RadioState*) gameState->GetState("RadioState");
	if (state == NULL) {
		state = (RadioState*) gameState->CreateState("RadioState");
	}

	m_state = state;
}

// FUNCTION: LEGO1 0x1002ce10
// FUNCTION: BETA10 0x100f20f6
RadioState::RadioState()
{
	srand(Timer()->GetTime());

	MxS32 random = rand();
	m_activePlaylist = random % 3;

	m_playlists[0] = Playlist((MxU32*) g_jingles, sizeOfArray(g_jingles), Playlist::e_loop);
	m_playlists[0].m_nextIndex = (rand() % sizeOfArray(g_jingles));

	m_playlists[1] = Playlist((MxU32*) g_news, sizeOfArray(g_news), Playlist::e_loop);
	m_playlists[1].m_nextIndex = (rand() % sizeOfArray(g_news));

	m_playlists[2] = Playlist((MxU32*) g_songs, sizeOfArray(g_songs), Playlist::e_loop);
	m_playlists[2].m_nextIndex = (rand() % sizeOfArray(g_songs));

	m_active = FALSE;
}

// FUNCTION: LEGO1 0x1002d090
MxU32 RadioState::NextPlaylistObjectId()
{
	if (m_activePlaylist == 2) {
		m_activePlaylist = 0;
	}
	else {
		m_activePlaylist++;
	}

	return m_playlists[m_activePlaylist].Next();
}

// FUNCTION: LEGO1 0x1002d0c0
MxBool RadioState::IsRadioObjectId(const MxAtomId& p_atom, MxU32 p_objectId)
{
	if (*g_jukeboxScript == p_atom) {
		for (MxS16 i = 0; i < 3; i++) {
			if (m_playlists[i].Contains(p_objectId)) {
				return TRUE;
			}
		}
	}

	return FALSE;
}
