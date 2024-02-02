#include "mxaudiomanager.h"

DECOMP_SIZE_ASSERT(MxAudioManager, 0x30);

// GLOBAL: LEGO1 0x10102108
MxS32 MxAudioManager::g_count = 0;

// FUNCTION: LEGO1 0x100b8d00
MxAudioManager::MxAudioManager()
{
	Init();
}

// FUNCTION: LEGO1 0x100b8d90
MxAudioManager::~MxAudioManager()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100b8df0
void MxAudioManager::Init()
{
	this->m_volume = 100;
}

// FUNCTION: LEGO1 0x100b8e00
void MxAudioManager::Destroy(MxBool p_fromDestructor)
{
	this->m_criticalSection.Enter();
	g_count--;
	Init();
	this->m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxMediaManager::Destroy();
	}
}

// FUNCTION: LEGO1 0x100b8e40
MxResult MxAudioManager::InitPresenters()
{
	MxResult result = FAILURE;
	MxBool success = FALSE;

	if (MxMediaManager::InitPresenters() == SUCCESS) {
		this->m_criticalSection.Enter();
		success = TRUE;
		result = SUCCESS;
		g_count++;
	}

	if (result) {
		Destroy();
	}

	if (success) {
		this->m_criticalSection.Leave();
	}

	return result;
}

// FUNCTION: LEGO1 0x100b8e90
void MxAudioManager::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x100b8ea0
void MxAudioManager::SetVolume(MxS32 p_volume)
{
	this->m_criticalSection.Enter();
	this->m_volume = p_volume;
	this->m_criticalSection.Leave();
}
