#include "mxwavepresenter.h"

#include "decomp.h"
#include "define.h"
#include "mxautolocker.h"
#include "mxdssound.h"
#include "mxomni.h"
#include "mxsoundmanager.h"
#include "mxutil.h"

DECOMP_SIZE_ASSERT(MxWavePresenter, 0x6c);
DECOMP_SIZE_ASSERT(MxWavePresenter::WaveFormat, 0x18);

// FUNCTION: LEGO1 0x100b1ad0
void MxWavePresenter::Init()
{
	m_waveFormat = NULL;
	m_dsBuffer = NULL;
	m_chunkLength = 0;
	m_lockSize = 0;
	m_writtenChunks = 0;
	m_started = FALSE;
	m_is3d = FALSE;
	m_paused = FALSE;
}

// FUNCTION: LEGO1 0x100b1af0
MxResult MxWavePresenter::AddToManager()
{
	MxResult result = MxSoundPresenter::AddToManager();
	Init();
	return result;
}

// FUNCTION: LEGO1 0x100b1b10
void MxWavePresenter::Destroy(MxBool p_fromDestructor)
{
	if (m_dsBuffer) {
		m_dsBuffer->Stop();
		m_dsBuffer->Release();
	}

	if (m_waveFormat) {
		delete[] ((MxU8*) m_waveFormat);
	}

	Init();

	if (!p_fromDestructor) {
		MxSoundPresenter::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x100b1b60
MxS8 MxWavePresenter::GetPlayedChunks()
{
	DWORD dwCurrentPlayCursor, dwCurrentWriteCursor;
	MxS8 playedChunks = -1;

	if (m_dsBuffer->GetCurrentPosition(&dwCurrentPlayCursor, &dwCurrentWriteCursor) == DS_OK) {
		playedChunks = dwCurrentPlayCursor / m_chunkLength;
	}

	return playedChunks;
}

// FUNCTION: LEGO1 0x100b1ba0
MxBool MxWavePresenter::FUN_100b1ba0()
{
	return !m_started || GetPlayedChunks() != m_writtenChunks;
}

// FUNCTION: LEGO1 0x100b1bd0
void MxWavePresenter::WriteToSoundBuffer(void* p_audioPtr, MxU32 p_length)
{
	DWORD dwStatus;
	LPVOID pvAudioPtr1;
	DWORD dwOffset;
	LPVOID pvAudioPtr2;
	DWORD dwAudioBytes1;
	DWORD dwAudioBytes2;

	dwOffset = m_chunkLength * m_writtenChunks;
	m_dsBuffer->GetStatus(&dwStatus);

	if (dwStatus == DSBSTATUS_BUFFERLOST) {
		m_dsBuffer->Restore();
		m_dsBuffer->GetStatus(&dwStatus);
	}

	if (dwStatus != DSBSTATUS_BUFFERLOST) {
		if (m_action->GetFlags() & MxDSAction::c_looping) {
			m_writtenChunks++;
			m_lockSize = p_length;
		}
		else {
			m_writtenChunks = 1 - m_writtenChunks;
			m_lockSize = m_chunkLength;
		}

		if (m_dsBuffer->Lock(dwOffset, m_lockSize, &pvAudioPtr1, &dwAudioBytes1, &pvAudioPtr2, &dwAudioBytes2, 0) ==
			DS_OK) {
			memcpy(pvAudioPtr1, p_audioPtr, p_length);

			if (m_lockSize > p_length && !(m_action->GetFlags() & MxDSAction::c_looping)) {
				memset((MxU8*) pvAudioPtr1 + p_length, m_silenceData, m_lockSize - p_length);
			}

			m_dsBuffer->Unlock(pvAudioPtr1, m_lockSize, pvAudioPtr2, 0);
		}
	}
}

// FUNCTION: LEGO1 0x100b1cf0
void MxWavePresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		m_waveFormat = (WaveFormat*) new MxU8[chunk->GetLength()];
		memcpy(m_waveFormat, chunk->GetData(), chunk->GetLength());
		m_subscriber->FreeDataChunk(chunk);
		ParseExtra();
		ProgressTickleState(e_starting);
	}
}

// FUNCTION: LEGO1 0x100b1d50
void MxWavePresenter::StartingTickle()
{
	MxStreamChunk* chunk = CurrentChunk();

	if (chunk && m_action->GetElapsedTime() >= chunk->GetTime()) {
		MxU32 length = chunk->GetLength();
		WAVEFORMATEX waveFormatEx;

		m_chunkLength = length;
		memset(&waveFormatEx, 0, sizeof(waveFormatEx));

		waveFormatEx.wFormatTag = m_waveFormat->m_pcmWaveFormat.wf.wFormatTag;
		waveFormatEx.nChannels = m_waveFormat->m_pcmWaveFormat.wf.nChannels;
		waveFormatEx.nSamplesPerSec = m_waveFormat->m_pcmWaveFormat.wf.nSamplesPerSec;
		waveFormatEx.nAvgBytesPerSec = m_waveFormat->m_pcmWaveFormat.wf.nAvgBytesPerSec;
		waveFormatEx.nBlockAlign = m_waveFormat->m_pcmWaveFormat.wf.nBlockAlign;
		waveFormatEx.wBitsPerSample = m_waveFormat->m_pcmWaveFormat.wBitsPerSample;

		if (waveFormatEx.wBitsPerSample == 8) {
			m_silenceData = 0x7F;
		}

		if (waveFormatEx.wBitsPerSample == 16) {
			m_silenceData = 0;
		}

		DSBUFFERDESC desc;
		memset(&desc, 0, sizeof(desc));
		desc.dwSize = sizeof(desc);

		if (m_is3d) {
			desc.dwFlags = DSBCAPS_CTRLFREQUENCY | DSBCAPS_CTRL3D | DSBCAPS_CTRLVOLUME;
		}
		else {
			desc.dwFlags = DSBCAPS_CTRLFREQUENCY | DSBCAPS_CTRLPAN | DSBCAPS_CTRLVOLUME;
		}

		if (m_action->GetFlags() & MxDSAction::c_looping) {
			desc.dwBufferBytes = m_waveFormat->m_pcmWaveFormat.wf.nAvgBytesPerSec *
								 (m_action->GetDuration() / m_action->GetLoopCount()) / 1000;
		}
		else {
			desc.dwBufferBytes = 2 * length;
		}

		desc.lpwfxFormat = &waveFormatEx;

		if (MSoundManager()->GetDirectSound()->CreateSoundBuffer(&desc, &m_dsBuffer, NULL) != DS_OK) {
			EndAction();
		}
		else {
			SetVolume(((MxDSSound*) m_action)->GetVolume());
			ProgressTickleState(e_streaming);
		}
	}
}

// FUNCTION: LEGO1 0x100b1ea0
void MxWavePresenter::StreamingTickle()
{
	if (!m_currentChunk) {
		if (!(m_action->GetFlags() & MxDSAction::c_looping)) {
			MxStreamChunk* chunk = CurrentChunk();

			if (chunk && chunk->GetFlags() & MxDSChunk::c_end && !(chunk->GetFlags() & MxDSChunk::c_bit16)) {
				chunk->SetFlags(chunk->GetFlags() | MxDSChunk::c_bit16);

				m_currentChunk = new MxStreamChunk;
				MxU8* data = new MxU8[m_chunkLength];

				memset(data, m_silenceData, m_chunkLength);

				m_currentChunk->SetLength(m_chunkLength);
				m_currentChunk->SetData(data);
				m_currentChunk->SetTime(chunk->GetTime() + 1000);
				m_currentChunk->SetFlags(MxDSChunk::c_bit1);
			}
		}

		MxMediaPresenter::StreamingTickle();
	}
}

// FUNCTION: LEGO1 0x100b20c0
void MxWavePresenter::DoneTickle()
{
	if (m_dsBuffer) {
		DWORD dwCurrentPlayCursor, dwCurrentWriteCursor;
		m_dsBuffer->GetCurrentPosition(&dwCurrentPlayCursor, &dwCurrentWriteCursor);

		MxS8 playedChunks = dwCurrentPlayCursor / m_chunkLength;
		if (m_action->GetFlags() & MxDSAction::c_bit7 || m_action->GetFlags() & MxDSAction::c_looping ||
			(!(m_action->GetFlags() & MxDSAction::c_looping) &&
			 (m_writtenChunks != playedChunks || m_lockSize + (m_chunkLength * playedChunks) <= dwCurrentPlayCursor))) {
			MxMediaPresenter::DoneTickle();
		}
	}
	else {
		MxMediaPresenter::DoneTickle();
	}
}

// FUNCTION: LEGO1 0x100b2130
void MxWavePresenter::LoopChunk(MxStreamChunk* p_chunk)
{
	WriteToSoundBuffer(p_chunk->GetData(), p_chunk->GetLength());
	if (IsEnabled()) {
		m_subscriber->FreeDataChunk(p_chunk);
	}
}

// FUNCTION: LEGO1 0x100b2160
MxResult MxWavePresenter::PutData()
{
	MxAutoLocker lock(&m_criticalSection);

	if (IsEnabled()) {
		switch (m_currentTickleState) {
		case e_streaming:
			if (m_currentChunk && FUN_100b1ba0()) {
				WriteToSoundBuffer(m_currentChunk->GetData(), m_currentChunk->GetLength());
				m_subscriber->FreeDataChunk(m_currentChunk);
				m_currentChunk = NULL;
			}

			if (!m_started) {
				m_dsBuffer->SetCurrentPosition(0);

				if (m_dsBuffer->Play(0, 0, DSBPLAY_LOOPING) == DS_OK) {
					m_started = TRUE;
				}
			}
			break;
		case e_repeating:
			if (m_started) {
				break;
			}

			m_dsBuffer->SetCurrentPosition(0);

			if (m_dsBuffer->Play(0, 0, m_action->GetLoopCount() > 1) == DS_OK) {
				m_started = TRUE;
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b2280
void MxWavePresenter::EndAction()
{
	if (m_action) {
		MxAutoLocker lock(&m_criticalSection);
		MxMediaPresenter::EndAction();

		if (m_dsBuffer) {
			m_dsBuffer->Stop();
		}
	}
}

// FUNCTION: LEGO1 0x100b2300
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

// FUNCTION: LEGO1 0x100b2360
void MxWavePresenter::Enable(MxBool p_enable)
{
	if (IsEnabled() != p_enable) {
		MxSoundPresenter::Enable(p_enable);

		if (p_enable) {
			m_writtenChunks = 0;
			m_started = FALSE;
		}
		else if (m_dsBuffer) {
			m_dsBuffer->Stop();
		}
	}
}

// FUNCTION: LEGO1 0x100b23a0
void MxWavePresenter::ParseExtra()
{
	MxSoundPresenter::ParseExtra();

	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength & MAXWORD) {
		char extraCopy[512];
		memcpy(extraCopy, extraData, extraLength & MAXWORD);
		extraCopy[extraLength & MAXWORD] = '\0';

		char soundValue[512];
		if (KeyValueStringParse(soundValue, g_strSOUND, extraCopy)) {
			if (!strcmpi(soundValue, "FALSE")) {
				Enable(FALSE);
			}
		}
	}
}

// FUNCTION: LEGO1 0x100b2440
void MxWavePresenter::Pause()
{
	if (!m_paused && m_started) {
		if (m_dsBuffer) {
			m_dsBuffer->Stop();
		}
		m_paused = TRUE;
	}
}

// FUNCTION: LEGO1 0x100b2470
void MxWavePresenter::Resume()
{
	if (m_paused) {
		if (m_dsBuffer && m_started) {
			switch (m_currentTickleState) {
			case e_streaming:
				m_dsBuffer->Play(0, 0, DSBPLAY_LOOPING);
				break;
			case e_repeating:
				m_dsBuffer->Play(0, 0, m_action->GetLoopCount() > 1);
				break;
			case e_done:
				m_dsBuffer->Play(0, 0, 0);
			}
		}

		m_paused = FALSE;
	}
}
