#include "mxmusicmanager.h"

#include "mxomni.h"
#include "mxticklemanager.h"

#include <windows.h>

DECOMP_SIZE_ASSERT(MxMusicManager, 0x58);

// OFFSET: LEGO1 0x100c05a0
MxMusicManager::MxMusicManager()
{
	Init();
}

// OFFSET: LEGO1 0x100c0630
MxMusicManager::~MxMusicManager()
{
	Destroy(TRUE);
}

// OFFSET: LEGO1 0x100c0690
void MxMusicManager::Init()
{
	m_multiplier = 100;
	InitData();
}

// OFFSET: LEGO1 0x100c06a0
void MxMusicManager::InitData()
{
	m_MIDIStreamH = 0;
	m_MIDIInitialized = FALSE;
	m_unk38 = 0;
	m_unk3c = 0;
	m_unk40 = 0;
	m_unk44 = 0;
	m_unk48 = 0;
	m_MIDIHdrP = NULL;
}

// OFFSET: LEGO1 0x100c06c0
void MxMusicManager::Destroy(MxBool p_fromDestructor)
{
	if (m_thread) {
		m_thread->Terminate();
		if (m_thread) {
			delete m_thread;
		}
	}
	else {
		TickleManager()->UnregisterClient(this);
	}

	m_criticalSection.Enter();
	DeinitializeMIDI();
	Init();
	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxAudioManager::Destroy();
	}
}

// OFFSET: LEGO1 0x100c07f0
void MxMusicManager::SetMIDIVolume()
{
	MxS32 result = (m_volume * m_multiplier) / 0x64;
	HMIDISTRM streamHandle = m_MIDIStreamH;

	if (streamHandle) {
		MxS32 volume = CalculateVolume(result);
		midiOutSetVolume((HMIDIOUT) streamHandle, volume);
	}
}

// OFFSET: LEGO1 0x100c0840
MxResult MxMusicManager::Create(MxU32 p_frequencyMS, MxBool p_createThread)
{
	MxResult status = FAILURE;
	MxBool locked = FALSE;

	if (MxAudioManager::InitPresenters() == SUCCESS) {
		if (p_createThread) {
			m_criticalSection.Enter();
			locked = TRUE;
			m_thread = new MxTickleThread(this, p_frequencyMS);

			if (!m_thread || m_thread->Start(0, 0) != SUCCESS)
				goto done;
		}
		else
			TickleManager()->RegisterClient(this, p_frequencyMS);

		status = SUCCESS;
	}

done:
	if (status != SUCCESS)
		Destroy();

	if (locked)
		m_criticalSection.Leave();

	return status;
}

// OFFSET: LEGO1 0x100c0930
void MxMusicManager::Destroy()
{
	Destroy(FALSE);
}

// OFFSET: LEGO1 0x100c0940
void MxMusicManager::SetVolume(MxS32 p_volume)
{
	MxAudioManager::SetVolume(p_volume);
	m_criticalSection.Enter();
	SetMIDIVolume();
	m_criticalSection.Leave();
}

// OFFSET: LEGO1 0x100c09a0
MxS32 MxMusicManager::CalculateVolume(MxS32 p_volume)
{
	MxS32 result = (p_volume * 0xffff) / 100;
	return (result << 0x10) | result;
}

// OFFSET: LEGO1 0x100c0b20
void MxMusicManager::DeinitializeMIDI()
{
	m_criticalSection.Enter();

	if (m_MIDIInitialized) {
		m_MIDIInitialized = FALSE;
		midiStreamStop(m_MIDIStreamH);
		midiOutUnprepareHeader((HMIDIOUT) m_MIDIStreamH, m_MIDIHdrP, sizeof(MIDIHDR));
		midiOutSetVolume((HMIDIOUT) m_MIDIStreamH, m_MIDIVolume);
		midiStreamClose(m_MIDIStreamH);
		delete m_MIDIHdrP;
		InitData();
	}

	m_criticalSection.Leave();
}
