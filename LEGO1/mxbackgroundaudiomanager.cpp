#include "mxbackgroundaudiomanager.h"

#include "legoomni.h"
#include "mxcompositepresenter.h"
#include "mxdssound.h"
#include "mxomni.h"
#include "mxpresenter.h"
#include "mxstreamer.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxBackgroundAudioManager, 0x150)

// OFFSET: LEGO1 0x1007ea90
MxBackgroundAudioManager::MxBackgroundAudioManager()
{
	NotificationManager()->Register(this);
	m_unka0 = 0;
	m_unk138 = 0;
	m_unk13c = 0;
	m_unk140 = 0;
	m_targetVolume = 0;
	m_unk148 = 0;
	m_musicEnabled = FALSE;
}

// OFFSET: LEGO1 0x1007ec20
MxBackgroundAudioManager::~MxBackgroundAudioManager()
{
	TickleManager()->UnregisterClient(this);
	NotificationManager()->Unregister(this);
	DestroyMusic();
}

// OFFSET: LEGO1 0x1007ece0
MxResult MxBackgroundAudioManager::Create(MxAtomId& p_script, MxU32 p_frequencyMS)
{
	MxResult result = OpenMusic(p_script);

	if (result == SUCCESS) {
		TickleManager()->RegisterClient(this, p_frequencyMS);
		m_musicEnabled = TRUE;
	}

	return result;
}

// OFFSET: LEGO1 0x1007ed20
MxResult MxBackgroundAudioManager::OpenMusic(MxAtomId& p_script)
{
	if (m_script.GetInternal())
		DestroyMusic();

	MxResult result = FAILURE;

	if (Streamer()->Open(p_script.GetInternal(), 0)) {
		m_script = p_script;
		result = SUCCESS;
	}

	return result;
}

// OFFSET: LEGO1 0x1007ed70
void MxBackgroundAudioManager::DestroyMusic()
{
	if (m_script.GetInternal()) {
		MxDSAction ds;
		ds.SetAtomId(m_script);
		ds.SetUnknown24(-2);
		DeleteObject(ds);
		Streamer()->Close(m_script.GetInternal());
		m_musicEnabled = FALSE;
	}
}

// OFFSET: LEGO1 0x1007ee40
MxResult MxBackgroundAudioManager::Tickle()
{
	switch (m_unk13c) {
	case MxPresenter::TickleState_Starting:
		FadeInOrFadeOut();
		return SUCCESS;
	case MxPresenter::TickleState_Streaming:
		FUN_1007ee70();
		return SUCCESS;
	case MxPresenter::TickleState_Repeating:
		FUN_1007ef40();
		return SUCCESS;
	default:
		return SUCCESS;
	}
}

// OFFSET: LEGO1 0x1007ee70
void MxBackgroundAudioManager::FUN_1007ee70()
{
	if (m_unka0 && m_unka0->GetAction()) {
		DeleteObject(*m_unk138->GetAction());
	}

	if (m_unk138) {
		m_unka0 = m_unk138;
		m_action1 = m_action2;
		m_unk138 = NULL;
		m_action2.SetObjectId(-1);
		m_action2.SetAtomId(MxAtomId());
		m_unk13c = NULL;
	}
}

// OFFSET: LEGO1 0x1007ef40
void MxBackgroundAudioManager::FUN_1007ef40()
{
	MxU32 compare;
	MxU32 volume;
	if (m_unka0 == NULL) {
		if (m_unk138) {
			compare = 30;
			if (m_unk148 == 0) {
				compare = m_unk148;
			}
			volume = m_unk138->GetVolume();
			if (volume < compare) {
				if (m_unk140 + m_unk138->GetVolume() <= compare) {
					compare = m_unk140 + compare;
				}
				m_unk138->SetVolume(compare);
			}
			else {
				m_unk138->SetVolume(compare);
				m_unka0 = m_unk138;
				m_action1 = m_action2;
				m_unk138 = NULL;
				m_action2.SetObjectId(-1);
				m_action2.SetAtomId(MxAtomId());
				m_unk13c = NULL;
			}
		}
	}
	else if (m_unka0->GetAction() != NULL) {
		if (m_unka0->GetVolume() == 0) {
			DeleteObject(*m_unka0->GetAction());
		}
		else {
			compare = m_unka0->GetVolume();
			volume = 0;
			if (compare != m_unk140 && -1 < compare - m_unk140) {
				volume = m_unka0->GetVolume() - m_unk140;
			}
			m_unk138->SetVolume(volume);
		}
	}
}

// OFFSET: LEGO1 0x1007f0e0
void MxBackgroundAudioManager::FadeInOrFadeOut()
{
	// This function probably is the fade in/out routine
	if (m_unka0 != NULL) {
		undefined4 volume = m_unka0->GetVolume();
		MxU32 compare = 30;
		if (m_unk148 == 0) {
			compare = m_targetVolume;
		}

		if (volume < compare) {
			volume = m_unk140 + volume;
			if (compare <= volume) {
				volume = compare;
			}
			m_unka0->SetVolume(volume);
		}
		else if (compare < volume) {
			volume = volume - m_unk140;
			if (volume <= compare) {
				volume = compare;
			}
			m_unka0->SetVolume(volume);
		}
		else {
			m_unka0->SetVolume(volume);
			m_unk13c = 0;
		}
	}
	else {
		m_unk13c = 0;
	}
}

// OFFSET: LEGO1 0x1007f170
MxLong MxBackgroundAudioManager::Notify(MxParam& p)
{
	switch (((MxNotificationParam&) p).GetNotification()) {
	case c_notificationStartAction:
		StartAction(p);
		return 1;
	case c_notificationEndAction:
		StopAction(p);
		return 1;
	}
	return 0;
}

// OFFSET: LEGO1 0x1007f1b0
void MxBackgroundAudioManager::StartAction(MxParam& p)
{
	// TODO: the sender is most likely a MxAudioPresenter?
	m_unk138 = (MxAudioPresenter*) ((MxNotificationParam&) p).GetSender();
	m_action2.SetAtomId(m_unk138->GetAction()->GetAtomId());
	m_action2.SetObjectId(m_unk138->GetAction()->GetObjectId());
	m_targetVolume = ((MxDSSound*) (m_unk138->GetAction()))->GetVolume();
	m_unk138->SetVolume(0);
}

// OFFSET: LEGO1 0x1007f200
void MxBackgroundAudioManager::StopAction(MxParam& p)
{
	if (((MxNotificationParam&) p).GetSender() == m_unka0) {
		m_unka0 = NULL;
		m_action1.SetAtomId(MxAtomId());
		m_action1.SetObjectId(-1);
	}
	else if (((MxNotificationParam&) p).GetSender() == m_unk138) {
		m_unk138 = NULL;
		m_action2.SetAtomId(MxAtomId());
		m_action2.SetObjectId(-1);
	}

	Lego()->HandleNotificationType2(p);
}

// OFFSET: LEGO1 0x1007f2f0
MxResult MxBackgroundAudioManager::PlayMusic(MxDSAction& p_action, undefined4 p_unknown, undefined4 p_unknown2)
{
	if (!m_musicEnabled) {
		return SUCCESS;
	}
	if (m_action2.GetObjectId() == -1 && m_action1.GetObjectId() != p_action.GetObjectId()) {
		MxDSAction action;
		action.SetAtomId(GetCurrentAction().GetAtomId());
		action.SetObjectId(GetCurrentAction().GetObjectId());
		action.SetUnknown24(GetCurrentAction().GetUnknown24());

		m_action2.SetAtomId(p_action.GetAtomId());
		m_action2.SetObjectId(p_action.GetObjectId());
		m_action2.SetUnknown84(this);
		m_action2.SetUnknown8c(this);

		MxResult result = Start(&m_action2);

		GetCurrentAction().SetAtomId(action.GetAtomId());
		GetCurrentAction().SetObjectId(action.GetObjectId());
		GetCurrentAction().SetUnknown24(action.GetUnknown24());

		if (result == SUCCESS) {
			m_unk13c = p_unknown2;
			m_unk140 = p_unknown;
		}
		return result;
	}
	return FAILURE;
}

// OFFSET: LEGO1 0x1007f470
void MxBackgroundAudioManager::Stop()
{
	if (m_action2.GetObjectId() != -1)
		DeleteObject(m_action2);

	m_unk138 = 0;
	m_action2.SetAtomId(MxAtomId());
	m_action2.SetObjectId(-1);

	if (m_action1.GetObjectId() != -1)
		DeleteObject(m_action1);

	m_unka0 = 0;
	m_action1.SetAtomId(MxAtomId());
	m_unk148 = 0;
	m_action1.SetObjectId(-1);
	m_unk13c = 0;
}

// OFFSET: LEGO1 0x1007f570
void MxBackgroundAudioManager::LowerVolume()
{
	if (m_unk148 == 0) {
		if (m_unk13c == 0) {
			m_unk13c = 2;
		}
		m_unk140 = 20;
	}
	m_unk148++;
}

// OFFSET: LEGO1 0x1007f5b0
void MxBackgroundAudioManager::RaiseVolume()
{
	if (m_unk148 != 0) {
		m_unk148--;
		if (m_unk148 == 0) {
			if (m_unk13c == 0) {
				m_unk13c = 2;
			}
			m_unk140 = 10;
		}
	}
}

// OFFSET: LEGO1 0x1007f5f0
void MxBackgroundAudioManager::Enable(MxBool p)
{
	if (this->m_musicEnabled != p) {
		this->m_musicEnabled = p;
		if (!p) {
			Stop();
		}
	}
}

// OFFSET: LEGO1 0x1007f650
void MxBackgroundAudioManager::Init()
{
	this->m_unka0 = 0;
	this->m_unk13c = 0;
}
