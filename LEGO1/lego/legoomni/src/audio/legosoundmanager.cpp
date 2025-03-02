#include "legosoundmanager.h"

#include "legocachesoundmanager.h"
#include "mxautolock.h"
#include "mxomni.h"

#include <assert.h>

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
// FUNCTION: BETA10 0x100d0129
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
		assert(m_cacheSoundManager);
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
// FUNCTION: BETA10 0x100d02ed
void LegoSoundManager::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1002a3a0
// FUNCTION: BETA10 0x100d030d
MxResult LegoSoundManager::Tickle()
{
	MxSoundManager::Tickle();

	AUTOLOCK(m_criticalSection);
	return m_cacheSoundManager->Tickle();
}

// FUNCTION: LEGO1 0x1002a410
// FUNCTION: BETA10 0x100d03a5
void LegoSoundManager::UpdateListener(
	const float* p_position,
	const float* p_direction,
	const float* p_up,
	const float* p_velocity
)
{
	if (m_listener != NULL) {
		if (p_position != NULL) {
			m_listener->SetPosition(p_position[0], p_position[1], p_position[2], DS3D_DEFERRED);
		}

		if (p_direction != NULL && p_up != NULL) {
			m_listener->SetOrientation(
				p_direction[0],
				p_direction[1],
				p_direction[2],
				p_up[0],
				p_up[1],
				p_up[2],
				DS3D_DEFERRED
			);
		}

		if (p_velocity != NULL) {
			m_listener->SetVelocity(p_velocity[0], p_velocity[1], p_velocity[2], DS3D_DEFERRED);
		}

		if (p_position != NULL || (p_direction != NULL && p_up != NULL) || p_velocity != NULL) {
			m_listener->CommitDeferredSettings();
		}
	}
}
