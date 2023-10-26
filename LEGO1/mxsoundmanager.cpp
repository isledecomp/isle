#include "mxsoundmanager.h"

#include "mxautolocker.h"
#include "mxomni.h"
#include "mxpresenter.h"
#include "mxticklemanager.h"
#include "mxwavepresenter.h"

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
	m_unk30 = 0;
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

// OFFSET: LEGO1 0x100ae8b0 STUB
MxResult MxSoundManager::Create(MxU32 p_frequencyMS, MxBool p_createThread)
{
	// TODO
	return FAILURE;
}

// OFFSET: LEGO1 0x100aed10
void MxSoundManager::vtable0x34()
{
	MxAutoLocker lock(&m_criticalSection);

	MxPresenter* presenter;
	MxPresenterListCursor cursor(m_presenters);

	while (cursor.Next(presenter))
		if (presenter->IsA("MxWavePresenter"))
			((MxWavePresenter*) presenter)->VTable0x64();
}

// OFFSET: LEGO1 0x100aee10
void MxSoundManager::vtable0x38()
{
	MxAutoLocker lock(&m_criticalSection);

	MxPresenter* presenter;
	MxPresenterListCursor cursor(m_presenters);

	while (cursor.Next(presenter))
		if (presenter->IsA("MxWavePresenter"))
			((MxWavePresenter*) presenter)->VTable0x68();
}

// OFFSET: LEGO1 0x100aeab0
void MxSoundManager::Destroy()
{
	Destroy(FALSE);
}

// OFFSET: LEGO1 0x100aeac0
void MxSoundManager::SetVolume(MxS32 p_volume)
{
	MxAudioManager::SetVolume(p_volume);

	m_criticalSection.Enter();

	MxPresenter* presenter;
	MxPresenterListCursor cursor(m_presenters);

	while (cursor.Next(presenter))
		((MxAudioPresenter*) presenter)->vtable60(((MxAudioPresenter*) presenter)->vtable5c());

	m_criticalSection.Leave();
}
