#include "lego3dsound.h"

#include "legoactor.h"
#include "legocharactermanager.h"
#include "misc.h"
#include "mxomni.h"

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
	m_unk0x14 = FALSE;
	m_isCharacter = FALSE;
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

		m_ds3dBuffer->SetMinDistance(15.0f, 0);
		m_ds3dBuffer->SetMaxDistance(100.0f, 0);
		m_ds3dBuffer->SetPosition(0.0f, 0.0f, -40.0f, 0);
		m_ds3dBuffer->SetConeOutsideVolume(-10000, 0);
	}

	if (m_ds3dBuffer == NULL || p_name == NULL) {
		return SUCCESS;
	}
	if (CharacterManager()->Exists(p_name)) {
		m_roi = CharacterManager()->GetROI(p_name, TRUE);
		m_unk0x14 = m_isCharacter = TRUE;
	}
	else {
		m_roi = FindROI(p_name);
	}

	if (m_roi == NULL) {
		m_roi = CharacterManager()->FUN_10085210(NULL, p_name, TRUE);

		if (m_roi != NULL) {
			m_unk0x14 = TRUE;
		}
	}

	if (m_roi == NULL) {
		return SUCCESS;
	}

	if (m_isCharacter) {
		m_positionROI = m_roi->FindChildROI("head", m_roi);
	}
	else {
		m_positionROI = m_roi;
	}

	if (MxOmni::IsSound3D()) {
		const float* position = m_positionROI->GetWorldPosition();
		m_ds3dBuffer->SetPosition(position[0], position[1], position[2], 0);
	}

	LegoEntity* entity = m_roi->GetEntity();
	if (entity != NULL && entity->IsA("LegoActor") && ((LegoActor*) entity)->VTable0x50() != 0.0f) {
		m_actor = ((LegoActor*) entity);
	}

	p_directSoundBuffer->GetFrequency(&m_dwFrequency);

	if (m_actor != NULL) {
		m_unk0x20 = m_actor->VTable0x50();

		if (m_unk0x20 != 0.0) {
			p_directSoundBuffer->SetFrequency(m_unk0x20 * m_dwFrequency);
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

	if (m_unk0x14 && m_roi && CharacterManager()) {
		if (m_isCharacter) {
			CharacterManager()->FUN_10083db0(m_roi);
		}
		else {
			CharacterManager()->FUN_10083f10(m_roi);
		}
	}

	Init();
}

// STUB: LEGO1 0x100118e0
// FUNCTION: BETA10 0x10039a2a
undefined4 Lego3DSound::FUN_100118e0(LPDIRECTSOUNDBUFFER p_directSoundBuffer)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10011ca0
void Lego3DSound::FUN_10011ca0()
{
	// TODO
}

// STUB: LEGO1 0x10011cf0
MxS32 Lego3DSound::FUN_10011cf0(undefined4, undefined4)
{
	// TODO
	return 0;
}
