#include "mxaudiomanager.h"

DECOMP_SIZE_ASSERT(MxAudioManager, 0x30);

// GLOBAL: LEGO1 0x10102108
MxS32 MxAudioManager::g_unkCount = 0;

// OFFSET: LEGO1 0x10029910
MxS32 MxAudioManager::GetVolume()
{
	return this->m_volume;
}

// OFFSET: LEGO1 0x100b8d00
MxAudioManager::MxAudioManager()
{
	Init();
}

// OFFSET: LEGO1 0x100b8d90
MxAudioManager::~MxAudioManager()
{
	Destroy(TRUE);
}

// OFFSET: LEGO1 0x100b8df0
void MxAudioManager::Init()
{
	this->m_volume = 100;
}

// OFFSET: LEGO1 0x100b8e00
void MxAudioManager::Destroy(MxBool p_fromDestructor)
{
	this->m_criticalSection.Enter();
	g_unkCount--;
	Init();
	this->m_criticalSection.Leave();

	if (!p_fromDestructor)
		MxMediaManager::Destroy();
}

// OFFSET: LEGO1 0x100b8e40
MxResult MxAudioManager::InitPresenters()
{
	MxResult result = FAILURE;
	MxBool success = FALSE;

	if (MxMediaManager::InitPresenters() == SUCCESS) {
		this->m_criticalSection.Enter();
		success = TRUE;
		result = SUCCESS;
		g_unkCount++;
	}

	if (result)
		Destroy();

	if (success)
		this->m_criticalSection.Leave();

	return result;
}

// OFFSET: LEGO1 0x100b8e90
void MxAudioManager::Destroy()
{
	Destroy(FALSE);
}

// OFFSET: LEGO1 0x100b8ea0
void MxAudioManager::SetVolume(MxS32 p_volume)
{
	this->m_criticalSection.Enter();
	this->m_volume = p_volume;
	this->m_criticalSection.Leave();
}
