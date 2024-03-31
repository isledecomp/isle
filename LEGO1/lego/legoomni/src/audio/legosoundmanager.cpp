#include "legosoundmanager.h"

#include "mxautolock.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(LegoSoundManager, 0x44)

// FUNCTION: LEGO1 0x100298a0
LegoSoundManager::LegoSoundManager()
{
	Init();
}

// FUNCTION: LEGO1 0x10029940
LegoSoundManager::~LegoSoundManager()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100299a0
void LegoSoundManager::Init()
{
	m_cacheSoundManager = NULL;
	m_listener = NULL;
}

// FUNCTION: LEGO1 0x100299b0
void LegoSoundManager::Destroy(MxBool p_fromDestructor)
{
	delete m_cacheSoundManager;
	Init();

	if (!p_fromDestructor) {
		MxSoundManager::Destroy();
	}
}

// FUNCTION: LEGO1 0x100299f0
MxResult LegoSoundManager::Create(MxU32 p_frequencyMS, MxBool p_createThread)
{
	MxBool locked = FALSE;
	MxResult result = FAILURE;

	if (MxSoundManager::Create(10, FALSE) == SUCCESS) {
		m_criticalSection.Enter();
		locked = TRUE;

		if (MxOmni::IsSound3D()) {
			if (m_dsBuffer->QueryInterface(IID_IDirectSound3DListener, (LPVOID*) &m_listener) != DS_OK) {
				goto done;
			}

			MxOmni* omni = MxOmni::GetInstance();
			LPDIRECTSOUND sound;

			if (omni && omni->GetSoundManager() && (sound = omni->GetSoundManager()->GetDirectSound())) {
				DSCAPS caps;
				memset(&caps, 0, sizeof(DSCAPS));
				caps.dwSize = sizeof(DSCAPS);

				if (sound->GetCaps(&caps) == S_OK && caps.dwMaxHw3DAllBuffers == 0) {
					m_listener->SetDistanceFactor(0.026315790f, 0);
					m_listener->SetRolloffFactor(10, 0);
				}
			}
		}

		m_cacheSoundManager = new LegoCacheSoundManager;
		result = SUCCESS;
	}

done:
	if (result != SUCCESS) {
		Destroy();
	}

	if (locked) {
		m_criticalSection.Leave();
	}

	return result;
}

// FUNCTION: LEGO1 0x1002a390
void LegoSoundManager::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1002a3a0
MxResult LegoSoundManager::Tickle()
{
	MxSoundManager::Tickle();

	AUTOLOCK(m_criticalSection);
	return m_cacheSoundManager->Tickle();
}

// STUB: LEGO1 0x1002a410
void LegoSoundManager::FUN_1002a410(const float* p_pos, const float* p_dir, const float* p_up, const float* p_vel)
{
	// TODO
}
