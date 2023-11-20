#include "mxwavepresenter.h"

#include "decomp.h"
#include "define.h"
#include "legoomni.h"
#include "mxautolocker.h"
#include "mxdssound.h"
#include "mxomni.h"
#include "mxsoundmanager.h"

#include <limits.h>

DECOMP_SIZE_ASSERT(MxWavePresenter, 0x6c);
DECOMP_SIZE_ASSERT(MxWavePresenter::WaveFormat, 0x1c);

// OFFSET: LEGO1 0x1000d640
MxWavePresenter::~MxWavePresenter()
{
	Destroy(TRUE);
}

// OFFSET: LEGO1 0x1000d6a0
void MxWavePresenter::Destroy()
{
	Destroy(FALSE);
}

// OFFSET: LEGO1 0x1000d6b0
MxBool MxWavePresenter::VTable0x6c()
{
	return m_unk68;
}

// OFFSET: LEGO1 0x100b1ad0
void MxWavePresenter::Init()
{
	m_waveFormat = NULL;
	m_dsBuffer = NULL;
	m_length = 0;
	m_bytes = 0;
	m_unk64 = 0;
	m_unk65 = FALSE;
	m_unk66 = FALSE;
	m_unk68 = FALSE;
}

// OFFSET: LEGO1 0x100b1af0
MxResult MxWavePresenter::AddToManager()
{
	MxResult result = MxSoundPresenter::AddToManager();
	Init();
	return result;
}

// OFFSET: LEGO1 0x100b1b10
void MxWavePresenter::Destroy(MxBool p_fromDestructor)
{
	if (m_dsBuffer) {
		m_dsBuffer->Stop();
		m_dsBuffer->Release();
	}

	if (m_waveFormat)
		delete[] ((MxU8*) m_waveFormat);

	Init();

	if (!p_fromDestructor)
		MxSoundPresenter::Destroy(FALSE);
}

// OFFSET: LEGO1 0x100b1b60
MxS8 MxWavePresenter::FUN_100b1b60()
{
	DWORD dwCurrentPlayCursor, dwCurrentWriteCursor;
	MxS8 result = -1;

	if (m_dsBuffer->GetCurrentPosition(&dwCurrentPlayCursor, &dwCurrentWriteCursor) == DS_OK)
		result = dwCurrentPlayCursor / m_length;

	return result;
}

// OFFSET: LEGO1 0x100b1ba0
MxBool MxWavePresenter::FUN_100b1ba0()
{
	return !m_unk65 || FUN_100b1b60() != m_unk64;
}

// OFFSET: LEGO1 0x100b1bd0
void MxWavePresenter::FUN_100b1bd0(void* p_audioPtr, MxU32 p_length)
{
	DWORD dwStatus;
	LPVOID pvAudioPtr1;
	DWORD dwOffset;
	LPVOID pvAudioPtr2;
	DWORD dwAudioBytes1;
	DWORD dwAudioBytes2;

	dwOffset = m_length * m_unk64;
	m_dsBuffer->GetStatus(&dwStatus);

	if (dwStatus == DSBSTATUS_BUFFERLOST) {
		m_dsBuffer->Restore();
		m_dsBuffer->GetStatus(&dwStatus);
	}

	if (dwStatus != DSBSTATUS_BUFFERLOST) {
		if (m_action->GetFlags() & MxDSAction::Flag_Looping) {
			m_unk64++;
			m_bytes = p_length;
		}
		else {
			m_unk64 = 1 - m_unk64;
			m_bytes = m_length;
		}

		if (m_dsBuffer->Lock(dwOffset, m_bytes, &pvAudioPtr1, &dwAudioBytes1, &pvAudioPtr2, &dwAudioBytes2, 0) ==
			DS_OK) {
			memcpy(pvAudioPtr1, p_audioPtr, p_length);

			// TODO

			if (m_bytes > p_length && !(m_action->GetFlags() & MxDSAction::Flag_Looping)) {
			}

			m_dsBuffer->Unlock(pvAudioPtr1, m_bytes, pvAudioPtr2, 0);
		}
	}
}

// OFFSET: LEGO1 0x100b1cf0
void MxWavePresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		m_waveFormat = (WaveFormat*) new MxU8[chunk->GetLength()];
		memcpy(m_waveFormat, chunk->GetData(), chunk->GetLength());
		m_subscriber->FUN_100b8390(chunk);
		ParseExtra();
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Starting;
	}
}

// OFFSET: LEGO1 0x100b1d50
void MxWavePresenter::StartingTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk && m_action->GetElapsedTime() >= chunk->GetTime()) {
		MxU32 length = chunk->GetLength();
		WAVEFORMATEX waveFormatEx;

		m_length = length;
		memset(&waveFormatEx, 0, sizeof(waveFormatEx));

		waveFormatEx.wFormatTag = m_waveFormat->m_waveFormatEx.wFormatTag;
		waveFormatEx.nChannels = m_waveFormat->m_waveFormatEx.nChannels;
		waveFormatEx.nSamplesPerSec = m_waveFormat->m_waveFormatEx.nSamplesPerSec;
		waveFormatEx.nAvgBytesPerSec = m_waveFormat->m_waveFormatEx.nAvgBytesPerSec;
		waveFormatEx.nBlockAlign = m_waveFormat->m_waveFormatEx.nBlockAlign;
		waveFormatEx.wBitsPerSample = m_waveFormat->m_waveFormatEx.wBitsPerSample;

		if (waveFormatEx.wBitsPerSample == 8)
			m_unk67 = SCHAR_MAX;

		if (waveFormatEx.wBitsPerSample == 16)
			m_unk67 = 0;

		DSBUFFERDESC desc;
		memset(&desc, 0, sizeof(desc));
		desc.dwSize = sizeof(desc);

		if (m_unk66)
			desc.dwFlags = DSBCAPS_CTRLFREQUENCY | DSBCAPS_CTRL3D | DSBCAPS_CTRLVOLUME;
		else
			desc.dwFlags = DSBCAPS_CTRLFREQUENCY | DSBCAPS_CTRLPAN | DSBCAPS_CTRLVOLUME;

		if (m_action->GetFlags() & MxDSAction::Flag_Looping)
			desc.dwBufferBytes = m_waveFormat->m_waveFormatEx.nAvgBytesPerSec *
								 (m_action->GetDuration() / m_action->GetLoopCount()) / 1000;
		else
			desc.dwBufferBytes = 2 * length;

		desc.lpwfxFormat = &waveFormatEx;

		if (MSoundManager()->GetDirectSound()->CreateSoundBuffer(&desc, &m_dsBuffer, NULL) != DS_OK) {
			EndAction();
		}
		else {
			SetVolume(((MxDSSound*) m_action)->GetVolume());
			m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
			m_currentTickleState = TickleState_Streaming;
		}
	}
}

// OFFSET: LEGO1 0x100b1ea0
void MxWavePresenter::StreamingTickle()
{
	if (!m_currentChunk) {
		if (!(m_action->GetFlags() & MxDSAction::Flag_Looping)) {
			MxStreamChunk* chunk = FUN_100b5650();

			if (chunk && chunk->GetFlags() & MxDSChunk::Flag_Bit2 && !(chunk->GetFlags() & MxDSChunk::Flag_Bit16)) {
				chunk->SetFlags(chunk->GetFlags() | MxDSChunk::Flag_Bit8);

				m_currentChunk = new MxStreamChunk;
				MxU8* data = new MxU8[m_length];

				// TODO

				m_currentChunk->SetLength(m_length);
				m_currentChunk->SetData(data);
				m_currentChunk->SetTime(chunk->GetTime() + 1000);
				m_currentChunk->SetFlags(MxDSChunk::Flag_Bit1);
			}
		}

		MxMediaPresenter::StreamingTickle();
	}
}

// OFFSET: LEGO1 0x100b20c0
void MxWavePresenter::DoneTickle()
{
	if (m_dsBuffer) {
		DWORD dwCurrentPlayCursor, dwCurrentWriteCursor;
		m_dsBuffer->GetCurrentPosition(&dwCurrentPlayCursor, &dwCurrentWriteCursor);

		MxS8 result = dwCurrentPlayCursor / m_length;
		if (m_action->GetFlags() & MxDSAction::Flag_Bit7 || m_action->GetFlags() & MxDSAction::Flag_Looping ||
			m_unk64 != result || m_bytes + (m_length * result) <= dwCurrentPlayCursor)
			MxMediaPresenter::DoneTickle();
	}
	else
		MxMediaPresenter::DoneTickle();
}

// OFFSET: LEGO1 0x100b2130
void MxWavePresenter::AppendChunk(MxStreamChunk* p_chunk)
{
	FUN_100b1bd0(p_chunk->GetData(), p_chunk->GetLength());
	if (IsEnabled())
		m_subscriber->FUN_100b8390(p_chunk);
}

// OFFSET: LEGO1 0x100b2160
undefined4 MxWavePresenter::PutData()
{
	MxAutoLocker lock(&m_criticalSection);

	if (IsEnabled()) {
		switch (m_currentTickleState) {
		case TickleState_Streaming:
			if (m_currentChunk && FUN_100b1ba0()) {
				FUN_100b1bd0(m_currentChunk->GetData(), m_currentChunk->GetLength());
				m_subscriber->FUN_100b8390(m_currentChunk);
				m_currentChunk = NULL;
			}

			if (!m_unk65) {
				m_dsBuffer->SetCurrentPosition(0);

				if (m_dsBuffer->Play(0, 0, DSBPLAY_LOOPING) == DS_OK)
					m_unk65 = TRUE;
			}
			break;
		case TickleState_Repeating:
			if (m_unk65)
				break;

			m_dsBuffer->SetCurrentPosition(0);

			if (m_dsBuffer->Play(0, 0, m_action->GetLoopCount() > 1) == DS_OK)
				m_unk65 = TRUE;
		}
	}

	return 0;
}

// OFFSET: LEGO1 0x100b2280
void MxWavePresenter::EndAction()
{
	if (m_action) {
		MxAutoLocker lock(&m_criticalSection);
		MxMediaPresenter::EndAction();

		if (m_dsBuffer)
			m_dsBuffer->Stop();
	}
}

// OFFSET: LEGO1 0x100b2300
void MxWavePresenter::SetVolume(MxS32 p_volume)
{
	m_criticalSection.Enter();

	m_volume = p_volume;
	if (m_dsBuffer != NULL) {
		MxS32 volume = p_volume * MxOmni::GetInstance()->GetSoundManager()->GetVolume() / 100;
		MxS32 otherVolume = MxOmni::GetInstance()->GetSoundManager()->FUN_100aecf0(volume);
		m_dsBuffer->SetVolume(otherVolume);
	}

	m_criticalSection.Leave();
}

// OFFSET: LEGO1 0x100b2360
void MxWavePresenter::Enable(MxBool p_enable)
{
	if (IsEnabled() != p_enable) {
		MxSoundPresenter::Enable(p_enable);

		if (p_enable) {
			m_unk64 = 0;
			m_unk65 = FALSE;
		}
		else if (m_dsBuffer)
			m_dsBuffer->Stop();
	}
}

// OFFSET: LEGO1 0x100b23a0
void MxWavePresenter::ParseExtra()
{
	char extraCopy[512];

	MxSoundPresenter::ParseExtra();
	*((MxU16*) &extraCopy[0]) = m_action->GetExtraLength();
	char* extraData = m_action->GetExtraData();

	if (*((MxU16*) &extraCopy[0])) {
		MxU16 len = *((MxU16*) &extraCopy[0]);
		memcpy(extraCopy, extraData, len);
		extraCopy[len] = '\0';

		char t_soundValue[512];
		if (KeyValueStringParse(t_soundValue, g_strSOUND, extraCopy)) {
			if (!strcmpi(t_soundValue, "FALSE"))
				Enable(FALSE);
		}
	}
}

// OFFSET: LEGO1 0x100b2440
void MxWavePresenter::VTable0x64()
{
	if (!m_unk68 && m_unk65) {
		if (m_dsBuffer)
			m_dsBuffer->Stop();
		m_unk68 = TRUE;
	}
}

// OFFSET: LEGO1 0x100b2470
void MxWavePresenter::VTable0x68()
{
	if (m_unk68) {
		if (m_dsBuffer && m_unk65) {
			switch (m_currentTickleState) {
			case TickleState_Streaming:
				m_dsBuffer->Play(0, 0, DSBPLAY_LOOPING);
				break;
			case TickleState_Repeating:
				m_dsBuffer->Play(0, 0, m_action->GetLoopCount() > 1);
				break;
			case TickleState_Done:
				m_dsBuffer->Play(0, 0, 0);
			}
		}

		m_unk68 = FALSE;
	}
}
