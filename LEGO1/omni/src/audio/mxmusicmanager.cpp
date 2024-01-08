#include "mxmusicmanager.h"

#include "mxomni.h"
#include "mxticklemanager.h"

#include <windows.h>

DECOMP_SIZE_ASSERT(MxMusicManager, 0x58);

// FUNCTION: LEGO1 0x100c05a0
MxMusicManager::MxMusicManager()
{
	Init();
}

// FUNCTION: LEGO1 0x100c0630
MxMusicManager::~MxMusicManager()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100c0690
void MxMusicManager::Init()
{
	m_multiplier = 100;
	InitData();
}

// FUNCTION: LEGO1 0x100c06a0
void MxMusicManager::InitData()
{
	m_midiStreamH = 0;
	m_midiInitialized = FALSE;
	m_unk0x38 = 0;
	m_unk0x3c = 0;
	m_unk0x40 = 0;
	m_unk0x44 = 0;
	m_unk0x48 = 0;
	m_midiHdrP = NULL;
}

// FUNCTION: LEGO1 0x100c06c0
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

// FUNCTION: LEGO1 0x100c07f0
void MxMusicManager::SetMIDIVolume()
{
	MxS32 result = (m_volume * m_multiplier) / 0x64;
	HMIDISTRM streamHandle = m_midiStreamH;

	if (streamHandle) {
		MxS32 volume = CalculateVolume(result);
		midiOutSetVolume((HMIDIOUT) streamHandle, volume);
	}
}

// FUNCTION: LEGO1 0x100c0840
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

// FUNCTION: LEGO1 0x100c0930
void MxMusicManager::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x100c0940
void MxMusicManager::SetVolume(MxS32 p_volume)
{
	MxAudioManager::SetVolume(p_volume);
	m_criticalSection.Enter();
	SetMIDIVolume();
	m_criticalSection.Leave();
}

// FUNCTION: LEGO1 0x100c0970
void MxMusicManager::SetMultiplier(MxS32 p_multiplier)
{
	m_criticalSection.Enter();
	m_multiplier = p_multiplier;
	SetMIDIVolume();
	m_criticalSection.Leave();
}

// FUNCTION: LEGO1 0x100c09a0
MxS32 MxMusicManager::CalculateVolume(MxS32 p_volume)
{
	MxS32 result = (p_volume * 0xffff) / 100;
	return (result << 0x10) | result;
}

// STUB: LEGO1 0x100c09c0
undefined4 MxMusicManager::FUN_100c09c0(MxU8* p_data, MxS32 p_loopCount)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x100c0b20
void MxMusicManager::DeinitializeMIDI()
{
	m_criticalSection.Enter();

	if (m_midiInitialized) {
		m_midiInitialized = FALSE;
		midiStreamStop(m_midiStreamH);
		midiOutUnprepareHeader((HMIDIOUT) m_midiStreamH, m_midiHdrP, sizeof(MIDIHDR));
		midiOutSetVolume((HMIDIOUT) m_midiStreamH, m_midiVolume);
		midiStreamClose(m_midiStreamH);
		delete m_midiHdrP;
		InitData();
	}

	m_criticalSection.Leave();
}
