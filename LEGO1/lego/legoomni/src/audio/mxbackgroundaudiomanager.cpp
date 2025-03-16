#include "mxbackgroundaudiomanager.h"

#include "legomain.h"
#include "misc.h"
#include "mxaudiopresenter.h"
#include "mxcompositepresenter.h"
#include "mxdssound.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxpresenter.h"
#include "mxstreamer.h"
#include "mxticklemanager.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(MxBackgroundAudioManager, 0x150)

// FUNCTION: LEGO1 0x1007ea90
MxBackgroundAudioManager::MxBackgroundAudioManager()
{
	NotificationManager()->Register(this);
	m_unk0xa0 = 0;
	m_unk0x138 = 0;
	m_tickleState = MxPresenter::e_idle;
	m_speed = 0;
	m_targetVolume = 0;
	m_unk0x148 = 0;
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
		FadeInOrFadeOut();
		break;
	case MxPresenter::e_streaming:
		FUN_1007ee70();
		break;
	case MxPresenter::e_repeating:
		FUN_1007ef40();
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1007ee70
void MxBackgroundAudioManager::FUN_1007ee70()
{
	if (m_unk0xa0 && m_unk0xa0->GetAction()) {
		DeleteObject(*m_unk0x138->GetAction());
	}

	if (m_unk0x138) {
		m_unk0xa0 = m_unk0x138;
		m_action1 = m_action2;
		m_unk0x138 = NULL;
		m_action2.SetObjectId(-1);
		m_action2.SetAtomId(MxAtomId());
		m_tickleState = MxPresenter::e_idle;
	}
}

// FUNCTION: LEGO1 0x1007ef40
void MxBackgroundAudioManager::FUN_1007ef40()
{
	MxS32 compare, volume;

	if (m_unk0xa0 == NULL) {
		if (m_unk0x138) {
			if (m_unk0x148 != 0) {
				compare = 30;
			}
			else {
				compare = m_targetVolume;
			}

			volume = m_unk0x138->GetVolume();
			if (volume < compare) {
				if (m_speed + m_unk0x138->GetVolume() <= compare) {
					compare = m_speed + m_unk0x138->GetVolume();
				}

				m_unk0x138->SetVolume(compare);
			}
			else {
				m_unk0x138->SetVolume(compare);
				m_unk0xa0 = m_unk0x138;
				m_action1 = m_action2;
				m_unk0x138 = NULL;
				m_action2.SetObjectId(-1);
				m_action2.SetAtomId(MxAtomId());
				m_tickleState = MxPresenter::e_idle;
			}
		}
	}
	else if (m_unk0xa0->GetAction() != NULL) {
		if (m_unk0xa0->GetVolume() == 0) {
			DeleteObject(*m_unk0xa0->GetAction());
		}
		else {
			if (m_unk0xa0->GetVolume() - m_speed > 0) {
				volume = m_unk0xa0->GetVolume() - m_speed;
			}
			else {
				volume = 0;
			}

			m_unk0xa0->SetVolume(volume);
		}
	}
}

// FUNCTION: LEGO1 0x1007f0e0
// FUNCTION: BETA10 0x100e8d8d
void MxBackgroundAudioManager::FadeInOrFadeOut()
{
	MxS32 volume, compare;

	if (m_unk0xa0 != NULL) {
		volume = m_unk0xa0->GetVolume();

		if (m_unk0x148 != 0) {
			compare = 30;
		}
		else {
			compare = m_targetVolume;
		}

		if (volume < compare) {
			m_unk0xa0->SetVolume(volume + m_speed < compare ? volume + m_speed : compare);
		}
		else if (compare < volume) {
			m_unk0xa0->SetVolume(volume - m_speed > compare ? volume - m_speed : compare);
		}
		else {
			m_unk0xa0->SetVolume(volume);
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
	m_unk0x138 = (MxAudioPresenter*) ((MxNotificationParam&) p_param).GetSender();
	m_action2.SetAtomId(m_unk0x138->GetAction()->GetAtomId());
	m_action2.SetObjectId(m_unk0x138->GetAction()->GetObjectId());
	m_targetVolume = ((MxDSSound*) (m_unk0x138->GetAction()))->GetVolume();
	m_unk0x138->SetVolume(0);
}

// FUNCTION: LEGO1 0x1007f200
void MxBackgroundAudioManager::StopAction(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetSender() == m_unk0xa0) {
		m_unk0xa0 = NULL;
		m_action1.SetAtomId(MxAtomId());
		m_action1.SetObjectId(-1);
	}
	else if (((MxNotificationParam&) p_param).GetSender() == m_unk0x138) {
		m_unk0x138 = NULL;
		m_action2.SetAtomId(MxAtomId());
		m_action2.SetObjectId(-1);
	}

	Lego()->HandleEndAction(p_param);
}

// FUNCTION: LEGO1 0x1007f2f0
// FUNCTION: BETA10 0x100e90fc
MxResult MxBackgroundAudioManager::PlayMusic(
	MxDSAction& p_action,
	undefined4 p_speed,
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
		m_action2.SetUnknown84(this);
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

	m_unk0x138 = 0;
	m_action2.SetAtomId(MxAtomId());
	m_action2.SetObjectId(-1);

	if (m_action1.GetObjectId() != -1) {
		DeleteObject(m_action1);
	}

	m_unk0xa0 = 0;
	m_action1.SetAtomId(MxAtomId());
	m_unk0x148 = 0;
	m_action1.SetObjectId(-1);
	m_tickleState = MxPresenter::e_idle;
}

// FUNCTION: LEGO1 0x1007f570
// FUNCTION: BETA10 0x100e94e6
void MxBackgroundAudioManager::LowerVolume()
{
	if (m_unk0x148 == 0) {
		if (m_tickleState == 0) {
			m_tickleState = MxPresenter::e_starting;
		}
		m_speed = 20;
	}
	m_unk0x148++;
}

// FUNCTION: LEGO1 0x1007f5b0
// FUNCTION: BETA10 0x100e9543
void MxBackgroundAudioManager::RaiseVolume()
{
	if (m_unk0x148 != 0) {
		m_unk0x148--;
		if (m_unk0x148 == 0) {
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
undefined4 MxBackgroundAudioManager::FUN_1007f610(
	MxPresenter* p_unk0x138,
	MxS32 p_speed,
	MxPresenter::TickleState p_tickleState
)

{
	m_unk0x138 = (MxAudioPresenter*) p_unk0x138;
	m_targetVolume = ((MxDSSound*) m_unk0x138->GetAction())->GetVolume();

	((MxCompositePresenter*) m_unk0x138)->VTable0x60(NULL);

	m_speed = p_speed;
	m_tickleState = p_tickleState;
	return 0;
}

// FUNCTION: LEGO1 0x1007f650
// FUNCTION: BETA10 0x100e9663
void MxBackgroundAudioManager::Init()
{
	this->m_unk0xa0 = 0;
	this->m_tickleState = MxPresenter::e_idle;
}
