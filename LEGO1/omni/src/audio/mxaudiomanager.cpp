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
	m_volume = 100;
}

// FUNCTION: LEGO1 0x100b8e00
void MxAudioManager::Destroy(MxBool p_fromDestructor)
{
	ENTER(m_criticalSection);
	g_count--;
	Init();
	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxMediaManager::Destroy();
	}
}

// FUNCTION: LEGO1 0x100b8e40
MxResult MxAudioManager::Create()
{
	MxResult result = FAILURE;
	MxBool success = FALSE;

	if (MxMediaManager::Create() == SUCCESS) {
		ENTER(m_criticalSection);
		success = TRUE;
		result = SUCCESS;
		g_count++;
	}

	if (result) {
		Destroy();
	}

	if (success) {
		m_criticalSection.Leave();
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
	ENTER(m_criticalSection);
	m_volume = p_volume;
	m_criticalSection.Leave();
}
