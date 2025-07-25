#include "mxbackgroundaudiomanager.h"

#include "legomain.h"
#include "misc.h"
#include "mxaudiopresenter.h"
#include "mxdssound.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxpresenter.h"
#include "mxstreamer.h"
#include "mxticklemanager.h"
#include "mxutilities.h"
#include "mxwavepresenter.h"

DECOMP_SIZE_ASSERT(MxBackgroundAudioManager, 0x150)

// FUNCTION: LEGO1 0x1007ea90
// FUNCTION: BETA10 0x100e8530
MxBackgroundAudioManager::MxBackgroundAudioManager()
{
	NotificationManager()->Register(this);
	m_activePresenter = NULL;
	m_pendingPresenter = NULL;
	m_tickleState = MxPresenter::e_idle;
	m_speed = 0;
	m_targetVolume = 0;
	m_volumeSuppressionAmount = 0;
	m_enabled = FALSE;
}

// FUNCTION: LEGO1 0x1007ec20
MxBackgroundAudioManager::~MxBackgroundAudioManager()
{
	TickleManager()->UnregisterClient(this);
	NotificationManager()->Unregister(this);
	DestroyMusic();
}

// FUNCTION: LEGO1 0x1007ece0
MxResult MxBackgroundAudioManager::Create(MxAtomId& p_script, MxU32 p_frequencyMS)
{
	MxResult result = OpenMusic(p_script);

	if (result == SUCCESS) {
		TickleManager()->RegisterClient(this, p_frequencyMS);
		m_enabled = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x1007ed20
MxResult MxBackgroundAudioManager::OpenMusic(MxAtomId& p_script)
{
	if (m_script.GetInternal()) {
		DestroyMusic();
	}

	MxResult result = FAILURE;

	if (Streamer()->Open(p_script.GetInternal(), 0)) {
		m_script = p_script;
		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x1007ed70
void MxBackgroundAudioManager::DestroyMusic()
{
	if (m_script.GetInternal()) {
		MxDSAction ds;
		ds.SetAtomId(m_script);
		ds.SetUnknown24(-2);
		DeleteObject(ds);
		Streamer()->Close(m_script.GetInternal());
		m_enabled = FALSE;
	}
}

// FUNCTION: LEGO1 0x1007ee40
MxResult MxBackgroundAudioManager::Tickle()
{
	switch (m_tickleState) {
	case MxPresenter::e_starting:
		FadeToTargetVolume();
		break;
	case MxPresenter::e_streaming:
		MakePendingPresenterActive();
		break;
	case MxPresenter::e_repeating:
		FadeInPendingPresenter();
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1007ee70
void MxBackgroundAudioManager::MakePendingPresenterActive()
{
	if (m_activePresenter && m_activePresenter->GetAction()) {
		DeleteObject(*m_pendingPresenter->GetAction());
	}

	if (m_pendingPresenter) {
		m_activePresenter = m_pendingPresenter;
		m_action1 = m_action2;
		m_pendingPresenter = NULL;
		m_action2.SetObjectId(-1);
		m_action2.SetAtomId(MxAtomId());
		m_tickleState = MxPresenter::e_idle;
	}
}

// FUNCTION: LEGO1 0x1007ef40
void MxBackgroundAudioManager::FadeInPendingPresenter()
{
	MxS32 compare, volume;

	if (m_activePresenter == NULL) {
		if (m_pendingPresenter) {
			if (m_volumeSuppressionAmount != 0) {
				compare = 30;
			}
			else {
				compare = m_targetVolume;
			}

			volume = m_pendingPresenter->GetVolume();
			if (volume < compare) {
				if (m_speed + m_pendingPresenter->GetVolume() <= compare) {
					compare = m_speed + m_pendingPresenter->GetVolume();
				}

				m_pendingPresenter->SetVolume(compare);
			}
			else {
				m_pendingPresenter->SetVolume(compare);
				m_activePresenter = m_pendingPresenter;
				m_action1 = m_action2;
				m_pendingPresenter = NULL;
				m_action2.SetObjectId(-1);
				m_action2.SetAtomId(MxAtomId());
				m_tickleState = MxPresenter::e_idle;
			}
		}
	}
	else if (m_activePresenter->GetAction() != NULL) {
		if (m_activePresenter->GetVolume() == 0) {
			DeleteObject(*m_activePresenter->GetAction());
		}
		else {
			if (m_activePresenter->GetVolume() - m_speed > 0) {
				volume = m_activePresenter->GetVolume() - m_speed;
			}
			else {
				volume = 0;
			}

			m_activePresenter->SetVolume(volume);
		}
	}
}

// FUNCTION: LEGO1 0x1007f0e0
// FUNCTION: BETA10 0x100e8d8d
void MxBackgroundAudioManager::FadeToTargetVolume()
{
	MxS32 volume, compare;

	if (m_activePresenter != NULL) {
		volume = m_activePresenter->GetVolume();

		if (m_volumeSuppressionAmount != 0) {
			compare = 30;
		}
		else {
			compare = m_targetVolume;
		}

		if (volume < compare) {
			m_activePresenter->SetVolume(volume + m_speed < compare ? volume + m_speed : compare);
		}
		else if (compare < volume) {
			m_activePresenter->SetVolume(volume - m_speed > compare ? volume - m_speed : compare);
		}
		else {
			m_activePresenter->SetVolume(volume);
			m_tickleState = MxPresenter::e_idle;
		}
	}
	else {
		m_tickleState = MxPresenter::e_idle;
	}
}

// FUNCTION: LEGO1 0x1007f170
// FUNCTION: BETA10 0x100e8eb6
MxLong MxBackgroundAudioManager::Notify(MxParam& p_param)
{
	MxNotificationParam& param = (MxNotificationParam&) p_param;

	switch (param.GetNotification()) {
	case c_notificationStartAction:
		StartAction(p_param);
		return 1;
	case c_notificationEndAction:
		StopAction(p_param);
		return 1;
	}
	return 0;
}

// FUNCTION: LEGO1 0x1007f1b0
void MxBackgroundAudioManager::StartAction(MxParam& p_param)
{
	// TODO: the sender is most likely a MxAudioPresenter?
	m_pendingPresenter = (MxAudioPresenter*) ((MxNotificationParam&) p_param).GetSender();
	m_action2.SetAtomId(m_pendingPresenter->GetAction()->GetAtomId());
	m_action2.SetObjectId(m_pendingPresenter->GetAction()->GetObjectId());
	m_targetVolume = ((MxDSSound*) (m_pendingPresenter->GetAction()))->GetVolume();
	m_pendingPresenter->SetVolume(0);
}

// FUNCTION: LEGO1 0x1007f200
void MxBackgroundAudioManager::StopAction(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetSender() == m_activePresenter) {
		m_activePresenter = NULL;
		m_action1.SetAtomId(MxAtomId());
		m_action1.SetObjectId(-1);
	}
	else if (((MxNotificationParam&) p_param).GetSender() == m_pendingPresenter) {
		m_pendingPresenter = NULL;
		m_action2.SetAtomId(MxAtomId());
		m_action2.SetObjectId(-1);
	}

	Lego()->HandleEndAction(p_param);
}

// FUNCTION: LEGO1 0x1007f2f0
// FUNCTION: BETA10 0x100e90fc
MxResult MxBackgroundAudioManager::PlayMusic(
	MxDSAction& p_action,
	MxS32 p_speed,
	MxPresenter::TickleState p_tickleState
)
{
	assert(p_speed > 0);

	if (!m_enabled) {
		return SUCCESS;
	}

	if (m_action2.GetObjectId() == -1 && m_action1.GetObjectId() != p_action.GetObjectId()) {
		MxDSAction action;
		action.SetAtomId(GetCurrentAction().GetAtomId());
		action.SetObjectId(GetCurrentAction().GetObjectId());
		action.SetUnknown24(GetCurrentAction().GetUnknown24());

		m_action2.SetAtomId(p_action.GetAtomId());
		m_action2.SetObjectId(p_action.GetObjectId());
		m_action2.SetNotificationObject(this);
		m_action2.SetOrigin(this);

		MxResult result = Start(&m_action2);

		GetCurrentAction().SetAtomId(action.GetAtomId());
		GetCurrentAction().SetObjectId(action.GetObjectId());
		GetCurrentAction().SetUnknown24(action.GetUnknown24());

		if (result == SUCCESS) {
			m_tickleState = p_tickleState;
			m_speed = p_speed;
		}

		return result;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x1007f470
// FUNCTION: BETA10 0x100e9388
void MxBackgroundAudioManager::Stop()
{
	if (m_action2.GetObjectId() != -1) {
		DeleteObject(m_action2);
	}

	m_pendingPresenter = NULL;
	m_action2.SetAtomId(MxAtomId());
	m_action2.SetObjectId(-1);

	if (m_action1.GetObjectId() != -1) {
		DeleteObject(m_action1);
	}

	m_activePresenter = NULL;
	m_action1.SetAtomId(MxAtomId());
	m_volumeSuppressionAmount = 0;
	m_action1.SetObjectId(-1);
	m_tickleState = MxPresenter::e_idle;
}

// FUNCTION: LEGO1 0x1007f570
// FUNCTION: BETA10 0x100e94e6
void MxBackgroundAudioManager::LowerVolume()
{
	if (m_volumeSuppressionAmount == 0) {
		if (m_tickleState == 0) {
			m_tickleState = MxPresenter::e_starting;
		}
		m_speed = 20;
	}
	m_volumeSuppressionAmount++;
}

// FUNCTION: LEGO1 0x1007f5b0
// FUNCTION: BETA10 0x100e9543
void MxBackgroundAudioManager::RaiseVolume()
{
	if (m_volumeSuppressionAmount != 0) {
		m_volumeSuppressionAmount--;
		if (m_volumeSuppressionAmount == 0) {
			if (m_tickleState == 0) {
				m_tickleState = MxPresenter::e_starting;
			}
			m_speed = 10;
		}
	}
}

// FUNCTION: LEGO1 0x1007f5f0
void MxBackgroundAudioManager::Enable(MxBool p_enable)
{
	if (this->m_enabled != p_enable) {
		this->m_enabled = p_enable;

		if (!p_enable) {
			Stop();
		}
	}
}

// FUNCTION: LEGO1 0x1007f610
// FUNCTION: BETA10 0x100e95ee
MxResult MxBackgroundAudioManager::SetPendingPresenter(
	MxPresenter* p_presenter,
	MxS32 p_speed,
	MxPresenter::TickleState p_tickleState
)

{
	m_pendingPresenter = (MxAudioPresenter*) p_presenter;
	m_targetVolume = ((MxDSSound*) m_pendingPresenter->GetAction())->GetVolume();

	((MxWavePresenter*) m_pendingPresenter)->SetVolume(0);

	m_speed = p_speed;
	m_tickleState = p_tickleState;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1007f650
// FUNCTION: BETA10 0x100e9663
void MxBackgroundAudioManager::Init()
{
	this->m_activePresenter = NULL;
	this->m_tickleState = MxPresenter::e_idle;
}
