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

// FUNCTION: LEGO1 0x10006630
LegoCacheSound::~LegoCacheSound()
{
	Destroy();
}

// FUNCTION: LEGO1 0x100066d0
void LegoCacheSound::Init()
{
	m_dsBuffer = NULL;
	m_data = NULL;
	m_unk0x58 = FALSE;
	memset(&m_wfx, 0, sizeof(m_wfx));
	m_unk0x6a = FALSE;
	m_unk0x70 = FALSE;
	m_looping = TRUE;
	m_volume = 79;
	m_muted = FALSE;
}

// FUNCTION: LEGO1 0x10006710
// FUNCTION: BETA10 0x10066505
MxResult LegoCacheSound::Create(
	LPPCMWAVEFORMAT p_pwfx,
	MxString p_mediaSrcPath,
	MxS32 p_volume,
	MxU8* p_data,
	MxU32 p_dataSize
)
{
	WAVEFORMATEX wfx;
	wfx.wFormatTag = p_pwfx->wf.wFormatTag;
	wfx.nChannels = p_pwfx->wf.nChannels;
	wfx.nSamplesPerSec = p_pwfx->wf.nSamplesPerSec;
	wfx.nAvgBytesPerSec = p_pwfx->wf.nAvgBytesPerSec;
	wfx.nBlockAlign = p_pwfx->wf.nBlockAlign;
	wfx.wBitsPerSample = p_pwfx->wBitsPerSample;
	wfx.cbSize = 0;

	DSBUFFERDESC desc;
	memset(&desc, 0, sizeof(desc));
	desc.dwSize = sizeof(desc);

	if (MxOmni::IsSound3D()) {
		desc.dwFlags =
			DSBCAPS_STATIC | DSBCAPS_LOCSOFTWARE | DSBCAPS_CTRL3D | DSBCAPS_CTRLFREQUENCY | DSBCAPS_CTRLVOLUME;
	}
	else {
		desc.dwFlags = DSBCAPS_CTRLFREQUENCY | DSBCAPS_CTRLPAN | DSBCAPS_CTRLVOLUME;
	}

	desc.dwBufferBytes = p_dataSize;
	desc.lpwfxFormat = &wfx;

	if (SoundManager()->GetDirectSound()->CreateSoundBuffer(&desc, &m_dsBuffer, NULL) != DS_OK) {
		return FAILURE;
	}

	m_volume = p_volume;

	MxS32 volume = m_volume * SoundManager()->GetVolume() / 100;
	MxS32 attenuation = SoundManager()->GetAttenuation(volume);
	m_dsBuffer->SetVolume(attenuation);

	if (m_sound.Create(m_dsBuffer, NULL, m_volume) != SUCCESS) {
		m_dsBuffer->Release();
		m_dsBuffer = NULL;
		return FAILURE;
	}

	if (p_data != NULL && p_dataSize != 0) {
		CopyData(p_data, p_dataSize);
	}

	m_unk0x48 = FUN_10006d80(p_mediaSrcPath);
	m_wfx = *p_pwfx;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100068e0
// FUNCTION: BETA10 0x100667a0
void LegoCacheSound::CopyData(MxU8* p_data, MxU32 p_dataSize)
{
	delete[] m_data;
	m_dataSize = p_dataSize;
	m_data = new MxU8[m_dataSize];
	memcpy(m_data, p_data, m_dataSize);
}

// FUNCTION: LEGO1 0x10006920
void LegoCacheSound::Destroy()
{
	if (m_dsBuffer) {
		m_dsBuffer->Stop();
		m_dsBuffer->Release();
		m_dsBuffer = NULL;
	}

	delete[] m_data;
	Init();
}

// FUNCTION: LEGO1 0x10006960
// FUNCTION: BETA10 0x100668cf
LegoCacheSound* LegoCacheSound::Clone()
{
	LegoCacheSound* pnew = new LegoCacheSound();

	if (pnew->Create(&m_wfx, m_unk0x48, m_volume, m_data, m_dataSize) == SUCCESS) {
		return pnew;
	}

	delete pnew;
	return NULL;
}

// FUNCTION: LEGO1 0x10006a30
// FUNCTION: BETA10 0x10066a23
MxResult LegoCacheSound::Play(const char* p_name, MxBool p_looping)
{
	if (m_data == NULL || m_dataSize == 0) {
		return FAILURE;
	}

	m_unk0x6a = FALSE;
	m_sound.FUN_10011a60(m_dsBuffer, p_name);

	if (p_name != NULL) {
		m_unk0x74 = p_name;
	}

	DWORD dwStatus;
	m_dsBuffer->GetStatus(&dwStatus);

	if (dwStatus == DSBSTATUS_BUFFERLOST) {
		m_dsBuffer->Restore();
		m_dsBuffer->GetStatus(&dwStatus);
	}

	if (dwStatus != DSBSTATUS_BUFFERLOST) {
		LPVOID pvAudioPtr1, pvAudioPtr2;
		DWORD dwAudioBytes1, dwAudioBytes2;

		if (m_dsBuffer->Lock(0, m_dataSize, &pvAudioPtr1, &dwAudioBytes1, &pvAudioPtr2, &dwAudioBytes2, 0) == DS_OK) {
			memcpy(pvAudioPtr1, m_data, dwAudioBytes1);

			if (dwAudioBytes2 != 0) {
				memcpy(pvAudioPtr2, m_data + dwAudioBytes1, dwAudioBytes2);
			}

			m_dsBuffer->Unlock(pvAudioPtr1, dwAudioBytes1, pvAudioPtr2, dwAudioBytes2);
			m_dsBuffer->SetCurrentPosition(0);
			m_dsBuffer->Play(0, 0, p_looping);
		}
	}

	if (p_looping == FALSE) {
		m_looping = FALSE;
	}
	else {
		m_looping = TRUE;
	}

	m_unk0x58 = TRUE;
	m_unk0x70 = TRUE;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10006b80
void LegoCacheSound::Stop()
{
	DWORD dwStatus;
	m_dsBuffer->GetStatus(&dwStatus);

	if (dwStatus) {
		m_dsBuffer->Stop();
	}

	m_unk0x58 = FALSE;
	m_unk0x6a = FALSE;

	m_sound.Reset();
	if (m_unk0x74.GetLength() != 0) {
		m_unk0x74 = "";
	}
}

// FUNCTION: LEGO1 0x10006be0
void LegoCacheSound::FUN_10006be0()
{
	if (!m_looping) {
		DWORD dwStatus;
		m_dsBuffer->GetStatus(&dwStatus);

		if (m_unk0x70) {
			if (dwStatus == 0) {
				return;
			}

			m_unk0x70 = FALSE;
		}

		if (dwStatus == 0) {
			m_dsBuffer->Stop();
			m_sound.Reset();
			if (m_unk0x74.GetLength() != 0) {
				m_unk0x74 = "";
			}

			m_unk0x58 = FALSE;
			return;
		}
	}

	if (m_unk0x74.GetLength() != 0 && !m_muted) {
		if (!m_sound.UpdatePosition(m_dsBuffer)) {
			if (m_unk0x6a) {
				return;
			}

			m_dsBuffer->Stop();
			m_unk0x6a = TRUE;
		}
		else if (m_unk0x6a) {
			m_dsBuffer->Play(0, 0, m_looping);
			m_unk0x6a = FALSE;
		}
	}
}

// FUNCTION: LEGO1 0x10006cb0
void LegoCacheSound::SetDistance(MxS32 p_min, MxS32 p_max)
{
	m_sound.SetDistance(p_min, p_max);
}

// FUNCTION: LEGO1 0x10006cd0
void LegoCacheSound::FUN_10006cd0(undefined4, undefined4)
{
}

// FUNCTION: LEGO1 0x10006d40
// FUNCTION: BETA10 0x10066ec8
void LegoCacheSound::Mute(MxBool p_muted)
{
	if (m_muted != p_muted) {
		m_muted = p_muted;

		if (m_muted) {
			m_dsBuffer->Stop();
		}
		else {
			m_dsBuffer->Play(0, 0, m_looping);
		}
	}
}

// FUNCTION: LEGO1 0x10006d80
// FUNCTION: BETA10 0x100670e7
MxString LegoCacheSound::FUN_10006d80(const MxString& p_str)
{
	// TODO: Clean up code
	char* str = p_str.GetData();
	MxU32 length = strlen(str);

	char* local28 = str + length;
	char* local14 = local28;
	char* pVar1 = local28;

	do {
		local14 = pVar1;
		pVar1 = local14 + -1;

		if (str == local14) {
			break;
		}

		if (*pVar1 == '.') {
			local28 = pVar1;
		}
	} while (*pVar1 != '\\');

	local14 = pVar1;

	MxString local24;
	local14++;
	*local28 = '\0';
	return local24 = local14;
}
