#include "mxaudiomanager.h"

DECOMP_SIZE_ASSERT(MxAudioManager, 0x30);

// GLOBAL: LEGO1 0x10102108
// GLOBAL: BETA10 0x10203a60
MxS32 MxAudioManager::g_count = 0;

// FUNCTION: LEGO1 0x100b8d00
// FUNCTION: BETA10 0x10144e90
MxAudioManager::MxAudioManager()
{
	Init();
}

// FUNCTION: LEGO1 0x100b8d90
// STUB: BETA10 0x10144f07
MxAudioManager::~MxAudioManager()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100b8df0
// FUNCTION: BETA10 0x10144f79
void MxAudioManager::Init()
{
	m_volume = 100;
}

// FUNCTION: LEGO1 0x100b8e00
// FUNCTION: BETA10 0x10144f9c
void MxAudioManager::Destroy(MxBool p_fromDestructor)
{
	ENTER(m_criticalSection);
	g_count--;
	Init();
	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxPresentationManager::Destroy();
	}
}

#ifdef BETA10
// FUNCTION: BETA10 0x10144ffe
MxResult MxAudioManager::Create()
{
	MxResult result = FAILURE;
	MxBool success = FALSE;

	if (MxPresentationManager::Create() != SUCCESS) {
		goto exit;
	}

	ENTER(m_criticalSection);
	success = TRUE;

	if (!g_count++) {
		// This is correct. It was likely refactored later.
	}

exit:
	result = SUCCESS;

	if (result) {
		Destroy();
	}

	if (success) {
		m_criticalSection.Leave();
	}

	return result;
}
#else
// FUNCTION: LEGO1 0x100b8e40
MxResult MxAudioManager::Create()
{
	MxResult result = FAILURE;
	MxBool success = FALSE;

	if (MxPresentationManager::Create() == SUCCESS) {
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
#endif

// FUNCTION: LEGO1 0x100b8e90
// FUNCTION: BETA10 0x101450a7
void MxAudioManager::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x100b8ea0
// FUNCTION: BETA10 0x101450c7
void MxAudioManager::SetVolume(MxS32 p_volume)
{
	ENTER(m_criticalSection);
	m_volume = p_volume;
	m_criticalSection.Leave();
}
