#include "lego3dsound.h"

#include "legoactor.h"
#include "legocharactermanager.h"
#include "legosoundmanager.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxomni.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(Lego3DSound, 0x30)

// FUNCTION: LEGO1 0x10011630
Lego3DSound::Lego3DSound()
{
	Init();
}

// FUNCTION: LEGO1 0x10011670
Lego3DSound::~Lego3DSound()
{
	Destroy();
}

// FUNCTION: LEGO1 0x10011680
void Lego3DSound::Init()
{
	m_ds3dBuffer = NULL;
	m_roi = NULL;
	m_positionROI = NULL;
	m_actor = NULL;
	m_enabled = FALSE;
	m_isActor = FALSE;
	m_volume = 79;
}

// FUNCTION: LEGO1 0x100116a0
// FUNCTION: BETA10 0x10039647
MxResult Lego3DSound::Create(LPDIRECTSOUNDBUFFER p_directSoundBuffer, const char* p_name, MxS32 p_volume)
{
	m_volume = p_volume;

	if (MxOmni::IsSound3D()) {
		p_directSoundBuffer->QueryInterface(IID_IDirectSound3DBuffer, (LPVOID*) &m_ds3dBuffer);
		if (m_ds3dBuffer == NULL) {
			return FAILURE;
		}

		m_ds3dBuffer->SetMinDistance(15.0f, DS3D_IMMEDIATE);
		m_ds3dBuffer->SetMaxDistance(100.0f, DS3D_IMMEDIATE);
		m_ds3dBuffer->SetPosition(0.0f, 0.0f, -40.0f, DS3D_IMMEDIATE);
		m_ds3dBuffer->SetConeOutsideVolume(-10000, DS3D_IMMEDIATE);
	}

	if (m_ds3dBuffer == NULL || p_name == NULL) {
		return SUCCESS;
	}

	if (CharacterManager()->IsActor(p_name)) {
		m_roi = CharacterManager()->GetActorROI(p_name, TRUE);
		m_enabled = m_isActor = TRUE;
	}
	else {
		m_roi = FindROI(p_name);
	}

	if (m_roi == NULL) {
		m_roi = CharacterManager()->CreateAutoROI(NULL, p_name, TRUE);

		if (m_roi != NULL) {
			m_enabled = TRUE;
		}
	}

	if (m_roi == NULL) {
		return SUCCESS;
	}

	if (m_isActor) {
		m_positionROI = m_roi->FindChildROI("head", m_roi);
	}
	else {
		m_positionROI = m_roi;
	}

	if (MxOmni::IsSound3D()) {
		const float* position = m_positionROI->GetWorldPosition();
		m_ds3dBuffer->SetPosition(position[0], position[1], position[2], DS3D_IMMEDIATE);
	}

	LegoEntity* entity = m_roi->GetEntity();
	if (entity != NULL && entity->IsA("LegoActor") && ((LegoActor*) entity)->GetSoundFrequencyFactor() != 0.0f) {
		m_actor = ((LegoActor*) entity);
	}

	p_directSoundBuffer->GetFrequency(&m_dwFrequency);

	if (m_actor != NULL) {
		m_frequencyFactor = m_actor->GetSoundFrequencyFactor();

		if (m_frequencyFactor != 0.0) {
			p_directSoundBuffer->SetFrequency(m_frequencyFactor * m_dwFrequency);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10011880
void Lego3DSound::Destroy()
{
	if (m_ds3dBuffer) {
		m_ds3dBuffer->Release();
		m_ds3dBuffer = NULL;
	}

	if (m_enabled && m_roi && CharacterManager()) {
		if (m_isActor) {
			CharacterManager()->ReleaseActor(m_roi);
		}
		else {
			CharacterManager()->ReleaseAutoROI(m_roi);
		}
	}

	Init();
}

// FUNCTION: LEGO1 0x100118e0
// FUNCTION: BETA10 0x10039a2a
MxU32 Lego3DSound::UpdatePosition(LPDIRECTSOUNDBUFFER p_directSoundBuffer)
{
	MxU32 updated = FALSE;

	if (m_positionROI != NULL) {
		const float* position = m_positionROI->GetWorldPosition();

		ViewROI* pov = VideoManager()->GetViewROI();
		assert(pov);

		const float* povPosition = pov->GetWorldPosition();
		float distance = DISTSQRD3(povPosition, position);

		if (distance > 10000.0f) {
			return FALSE;
		}

		if (m_ds3dBuffer != NULL) {
			m_ds3dBuffer->SetPosition(position[0], position[1], position[2], DS3D_IMMEDIATE);
		}
		else {
			MxS32 newVolume = m_volume;
			if (distance < 100.0f) {
				newVolume = m_volume;
			}
			else if (distance < 400.0f) {
				newVolume *= 0.4;
			}
			else if (distance < 3600.0f) {
				newVolume *= 0.1;
			}
			else if (distance < 10000.0f) {
				newVolume = 0;
			}

			newVolume = newVolume * SoundManager()->GetVolume() / 100;
			newVolume = SoundManager()->GetAttenuation(newVolume);
			p_directSoundBuffer->SetVolume(newVolume);
		}

		updated = TRUE;
	}

	if (m_actor != NULL) {
		if (abs(m_frequencyFactor - m_actor->GetSoundFrequencyFactor()) > 0.0001) {
			m_frequencyFactor = m_actor->GetSoundFrequencyFactor();
			p_directSoundBuffer->SetFrequency(m_frequencyFactor * m_dwFrequency);
			updated = TRUE;
		}
	}

	return updated;
}

// FUNCTION: LEGO1 0x10011a60
// FUNCTION: BETA10 0x10039d04
void Lego3DSound::FUN_10011a60(LPDIRECTSOUNDBUFFER p_directSoundBuffer, const char* p_name)
{
	assert(p_directSoundBuffer);

	if (p_name == NULL) {
		if (m_ds3dBuffer != NULL) {
			m_ds3dBuffer->SetMode(DS3DMODE_DISABLE, DS3D_IMMEDIATE);
		}
	}
	else {
		if (CharacterManager()->IsActor(p_name)) {
			m_roi = CharacterManager()->GetActorROI(p_name, TRUE);
			m_enabled = m_isActor = TRUE;
		}
		else {
			m_roi = FindROI(p_name);
		}

		if (m_roi == NULL) {
			m_roi = CharacterManager()->CreateAutoROI(NULL, p_name, TRUE);

			if (m_roi != NULL) {
				m_enabled = TRUE;
			}
		}

		if (m_roi == NULL) {
			return;
		}

		if (m_isActor) {
			m_positionROI = m_roi->FindChildROI("head", m_roi);
		}
		else {
			m_positionROI = m_roi;
		}

		if (m_ds3dBuffer != NULL) {
			DWORD dwMode;
			m_ds3dBuffer->GetMode(&dwMode);

			if (dwMode & DS3DMODE_DISABLE) {
				m_ds3dBuffer->SetMode(DS3DMODE_NORMAL, DS3D_IMMEDIATE);
			}

			const float* position = m_positionROI->GetWorldPosition();
			m_ds3dBuffer->SetPosition(position[0], position[1], position[2], DS3D_IMMEDIATE);
		}
		else {
			const float* position = m_positionROI->GetWorldPosition();
			ViewROI* pov = VideoManager()->GetViewROI();

			if (pov != NULL) {
				const float* povPosition = pov->GetWorldPosition();
				float distance = DISTSQRD3(povPosition, position);

				MxS32 newVolume;
				if (distance < 100.0f) {
					newVolume = m_volume;
				}
				else if (distance < 400.0f) {
					newVolume = m_volume * 0.4;
				}
				else if (distance < 3600.0f) {
					newVolume = m_volume * 0.1;
				}
				else {
					newVolume = 0;
				}

				newVolume = newVolume * SoundManager()->GetVolume() / 100;
				newVolume = SoundManager()->GetAttenuation(newVolume);
				p_directSoundBuffer->SetVolume(newVolume);
			}
		}

		LegoEntity* entity = m_roi->GetEntity();
		if (entity != NULL && entity->IsA("LegoActor") && ((LegoActor*) entity)->GetSoundFrequencyFactor() != 0.0f) {
			m_actor = ((LegoActor*) entity);
		}

		p_directSoundBuffer->GetFrequency(&m_dwFrequency);

		if (m_actor != NULL) {
			m_frequencyFactor = m_actor->GetSoundFrequencyFactor();

			if (m_frequencyFactor != 0.0) {
				p_directSoundBuffer->SetFrequency(m_frequencyFactor * m_dwFrequency);
			}
		}
	}
}

// FUNCTION: LEGO1 0x10011ca0
void Lego3DSound::Reset()
{
	if (m_enabled && m_roi && CharacterManager()) {
		if (m_isActor) {
			CharacterManager()->ReleaseActor(m_roi);
		}
		else {
			CharacterManager()->ReleaseAutoROI(m_roi);
		}
	}

	m_roi = NULL;
	m_positionROI = NULL;
	m_actor = NULL;
}

// FUNCTION: LEGO1 0x10011cf0
// FUNCTION: BETA10 0x10039fe0
MxS32 Lego3DSound::SetDistance(MxS32 p_min, MxS32 p_max)
{
	if (MxOmni::IsSound3D()) {
		if (m_ds3dBuffer == NULL) {
			return -1;
		}

		m_ds3dBuffer->SetMinDistance(p_min, DS3D_IMMEDIATE);
		m_ds3dBuffer->SetMaxDistance(p_max, DS3D_IMMEDIATE);
		return 0;
	}

	return 1;
}
