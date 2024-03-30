#include "legocachsound.h"

#include "legosoundmanager.h"
#include "misc.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(LegoCacheSound, 0x88)

// FUNCTION: LEGO1 0x100064d0
LegoCacheSound::LegoCacheSound()
{
	Init();
}

// STUB: LEGO1 0x10006630
LegoCacheSound::~LegoCacheSound()
{
	// TODO
	Destroy();
}

// FUNCTION: LEGO1 0x100066d0
void LegoCacheSound::Init()
{
	m_dsBuffer = NULL;
	m_unk0x40 = NULL;
	m_unk0x58 = 0;
	memset(&m_unk0x59, 0, sizeof(m_unk0x59));
	m_unk0x6a = FALSE;
	m_unk0x70 = 0;
	m_isLooping = TRUE;
	m_unk0x6c = 79;
	m_unk0x84 = 0;
}

// STUB: LEGO1 0x10006710
MxResult LegoCacheSound::FUN_10006710()
{
	// TODO
	DSBUFFERDESC desc;
	memset(&desc, 0, sizeof(desc));
	desc.dwSize = sizeof(desc);

	if (MxOmni::IsSound3D()) {
		desc.dwFlags = DSBCAPS_PRIMARYBUFFER | DSBCAPS_CTRL3D;
	}
	else {
		desc.dwFlags = DSBCAPS_PRIMARYBUFFER | DSBCAPS_CTRLVOLUME;
	}

	if (SoundManager()->GetDirectSound()->CreateSoundBuffer(&desc, &m_dsBuffer, NULL) != DS_OK) {
		return FAILURE;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10006920
void LegoCacheSound::Destroy()
{
	if (m_dsBuffer) {
		m_dsBuffer->Stop();
		m_dsBuffer->Release();
		m_dsBuffer = NULL;
	}

	delete m_unk0x40;
	Init();
}

// STUB: LEGO1 0x10006960
LegoCacheSound* LegoCacheSound::FUN_10006960()
{
	// TODO
	return NULL;
}

// STUB: LEGO1 0x10006a30
MxResult LegoCacheSound::FUN_10006a30(const char* p_str, MxBool)
{
	// TODO
	// gets param2 from FUN_1003db10
	if (!m_unk0x40 && !m_unk0x44) {
		return FAILURE;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10006b80
void LegoCacheSound::FUN_10006b80()
{
	DWORD dwStatus;

	m_dsBuffer->GetStatus(&dwStatus);
	if (dwStatus) {
		m_dsBuffer->Stop();
	}

	m_unk0x58 = 0;
	m_unk0x6a = FALSE;

	m_unk0x10.FUN_10011ca0();
	if (m_string0x74.GetLength() != 0) {
		m_string0x74 = "";
	}
}

// FUNCTION: LEGO1 0x10006be0
void LegoCacheSound::FUN_10006be0()
{
	if (!m_isLooping) {
		DWORD dwStatus;
		m_dsBuffer->GetStatus(&dwStatus);

		if (m_unk0x70) {
			if (dwStatus == 0) {
				return;
			}

			m_unk0x70 = 0;
		}

		if (dwStatus == 0) {
			m_dsBuffer->Stop();
			m_unk0x10.FUN_10011ca0();
			if (m_string0x74.GetLength() != 0) {
				m_string0x74 = "";
			}

			m_unk0x58 = 0;
			return;
		}
	}

	if (m_string0x74.GetLength() != 0 && !m_unk0x84) {
		if (!m_unk0x10.FUN_100118e0(m_dsBuffer)) {
			if (m_unk0x6a) {
				return;
			}

			m_dsBuffer->Stop();
			m_unk0x6a = TRUE;
		}
		else if (m_unk0x6a) {
			m_dsBuffer->Play(0, 0, m_isLooping);
			m_unk0x6a = FALSE;
		}
	}
}

// FUNCTION: LEGO1 0x10006cd0
void LegoCacheSound::FUN_10006cd0(undefined4, undefined4)
{
}
