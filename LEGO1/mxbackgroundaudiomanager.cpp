#include "mxbackgroundaudiomanager.h"

#include "mxomni.h"
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