#include "mxsoundmanager.h"

#include "mxomni.h"
#include "mxticklemanager.h"

DECOMP_SIZE_ASSERT(MxSoundManager, 0x3c);

// OFFSET: LEGO1 0x100ae740
MxSoundManager::MxSoundManager()
{
	Init();
}

// OFFSET: LEGO1 0x100ae7d0
MxSoundManager::~MxSoundManager()
{
	Destroy(TRUE);
}

// OFFSET: LEGO1 0x100ae830
void MxSoundManager::Init()
{
	m_directSound = NULL;
	m_dsBuffer = NULL;
}

// OFFSET: LEGO1 0x100ae840
void MxSoundManager::Destroy(MxBool p_fromDestructor)
{
	if (this->m_thread) {
		this->m_thread->Terminate();
		delete this->m_thread;
	}
	else {
		TickleManager()->UnregisterClient(this);
	}

	this->m_criticalSection.Enter();

	if (this->m_dsBuffer) {
		this->m_dsBuffer->Release();
	}

	Init();
	this->m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxAudioManager::Destroy();
	}
}

// OFFSET: LEGO1 0x100ae8b0
MxResult MxSoundManager::Create(MxU32 p_frequencyMS, MxBool p_createThread)
{
	MxResult status = FAILURE;
	MxBool locked = FALSE;

	if (MxAudioManager::InitPresenters() != SUCCESS)
		goto done;

	m_criticalSection.Enter();
	locked = TRUE;

	if (DirectSoundCreate(NULL, &m_directSound, NULL) != DS_OK)
		goto done;

	if (m_directSound->SetCooperativeLevel(MxOmni::GetInstance()->GetWindowHandle(), DSSCL_PRIORITY) != DS_OK)
		goto done;

	DSBUFFERDESC desc;
	memset(&desc, 0, sizeof(desc));
	desc.dwSize = sizeof(desc);

	if (MxOmni::IsSound3D())
		desc.dwFlags = DSBCAPS_PRIMARYBUFFER | DSBCAPS_CTRL3D;
	else
		desc.dwFlags = DSBCAPS_PRIMARYBUFFER | DSBCAPS_CTRLVOLUME;

	if (m_directSound->CreateSoundBuffer(&desc, &m_dsBuffer, NULL) != DS_OK) {
		if (!MxOmni::IsSound3D())
			goto done;

		MxOmni::SetSound3D(FALSE);
		desc.dwFlags = DSBCAPS_PRIMARYBUFFER | DSBCAPS_CTRLVOLUME;

		if (m_directSound->CreateSoundBuffer(&desc, &m_dsBuffer, NULL) != DS_OK)
			goto done;
	}

	WAVEFORMATEX format;

	format.wFormatTag = WAVE_FORMAT_PCM;

	if (MxOmni::IsSound3D())
		format.nChannels = 2;
	else
		format.nChannels = 1;

	format.nSamplesPerSec = 11025; // KHz
	format.wBitsPerSample = 16;
	format.nBlockAlign = format.nChannels * 2;
	format.nAvgBytesPerSec = format.nBlockAlign * 11025;
	format.cbSize = 0;

	status = m_dsBuffer->SetFormat(&format);

	if (p_createThread) {
		m_thread = new MxTickleThread(this, p_frequencyMS);

		if (!m_thread || m_thread->Start(0, 0) != SUCCESS)
			goto done;
	}
	else
		TickleManager()->RegisterClient(this, p_frequencyMS);

	status = SUCCESS;

done:
	if (status != SUCCESS)
		Destroy();

	if (locked)
		m_criticalSection.Leave();
	return status;
}

// OFFSET: LEGO1 0x100aed10 STUB
void MxSoundManager::vtable0x34()
{
	// TODO
}

// OFFSET: LEGO1 0x100aee10 STUB
void MxSoundManager::vtable0x38()
{
	// TODO
}

// OFFSET: LEGO1 0x100aeab0
void MxSoundManager::Destroy()
{
	Destroy(FALSE);
}

// OFFSET: LEGO1 0x100aeac0 STUB
void MxSoundManager::SetVolume(MxS32 p_volume)
{
	// TODO
}
