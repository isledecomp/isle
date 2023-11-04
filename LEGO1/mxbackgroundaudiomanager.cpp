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
	m_unk144 = 0;
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
void MxBackgroundAudioManager::FUN_1007f570()
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
void MxBackgroundAudioManager::FUN_1007f5b0()
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

// OFFSET: LEGO1 0x1007f170
MxResult MxBackgroundAudioManager::Notify(MxParam& p)
{
	if (((MxNotificationParam&) p).GetNotification() == c_notificationStartAction) {
		StartAction(p);
		return 1;
	}

	if (((MxNotificationParam&) p).GetNotification() != c_notificationEndAction) {
		return 0;
	}
	StopAction(p);
	return 1;
}

// Matches but register allocation is is different.
// OFFSET: LEGO1 0x1007f1b0
void MxBackgroundAudioManager::StartAction(MxParam& p)
{
	// TODO: the sender is most likely a MxCompositePresenter?
	m_unk138 = (MxCompositePresenter*) ((MxNotificationParam&) p).GetSender();
	m_action2.SetAtomId(m_unk138->GetAction()->GetAtomId());
	m_action2.SetObjectId(m_unk138->GetAction()->GetObjectId());
	m_unk144 = ((MxDSSound*) (m_unk138->GetAction()))->GetVolume();
	m_unk138->VTable0x60(0);
}

// OFFSET: LEGO1 0x1007f200
void MxBackgroundAudioManager::StopAction(MxParam& p)
{
	if (((MxNotificationParam&) p).GetSender() == m_unka0) {
		m_unka0 = NULL;
		m_action1.SetAtomId(MxAtomId());
		m_action1.SetObjectId(-1);
	}
	else {
		if (((MxNotificationParam&) p).GetSender() == m_unk138) {
			m_unk138 = NULL;
			m_action2.SetAtomId(MxAtomId());
			m_action2.SetObjectId(-1);
		}
	}

	Lego()->HandleNotificationType2(p);
}

// OFFSET: LEGO1 0x1007ee40 STUB
MxResult MxBackgroundAudioManager::Tickle()
{
	// TODO
	return FAILURE;
}
