#include "legoloadcachesoundpresenter.h"

#include "legocachesoundmanager.h"
#include "legocachsound.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "mxdssound.h"
#include "mxdssubscriber.h"
#include "mxstreamchunk.h"
#include "mxwavepresenter.h"

DECOMP_SIZE_ASSERT(LegoLoadCacheSoundPresenter, 0x90)

// FUNCTION: LEGO1 0x10018340
LegoLoadCacheSoundPresenter::LegoLoadCacheSoundPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x10018480
LegoLoadCacheSoundPresenter::~LegoLoadCacheSoundPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x100184e0
void LegoLoadCacheSoundPresenter::Init()
{
	m_data = NULL;
	m_dataSize = 0;
	m_unk0x7c = FALSE;
}

// FUNCTION: LEGO1 0x100184f0
void LegoLoadCacheSoundPresenter::Destroy(MxBool p_fromDestructor)
{
	delete[] m_data;
	MxWavePresenter::Destroy(p_fromDestructor);
}

// FUNCTION: LEGO1 0x10018510
// FUNCTION: BETA10 0x1008c305
void LegoLoadCacheSoundPresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		WaveFormat* header = (WaveFormat*) chunk->GetData();
		m_dataSize = 0;

		MxU8* data = new MxU8[header->m_dataSize];
		m_data = data;
		m_pData = data;

		m_cacheSound = new LegoCacheSound();
		m_pcmWaveFormat = header->m_pcmWaveFormat;

		m_subscriber->FreeDataChunk(chunk);
		ProgressTickleState(e_streaming);
	}
}

// FUNCTION: LEGO1 0x100185f0
// FUNCTION: BETA10 0x1008c48f
void LegoLoadCacheSoundPresenter::StreamingTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		if (chunk->GetChunkFlags() & DS_CHUNK_END_OF_STREAM) {
			m_cacheSound->Create(
				&m_pcmWaveFormat,
				((MxDSSound*) m_action)->GetMediaSrcPath(),
				((MxDSSound*) m_action)->GetVolume(),
				m_data + 2,
				m_dataSize - 2
			);
			ProgressTickleState(e_done);
		}
		else {
			memcpy(m_pData, chunk->GetData(), chunk->GetLength());
			m_dataSize += chunk->GetLength();
			m_pData += chunk->GetLength();
		}

		m_subscriber->FreeDataChunk(chunk);
	}
}

// FUNCTION: LEGO1 0x100186f0
void LegoLoadCacheSoundPresenter::DoneTickle()
{
	if (m_unk0x7c) {
		EndAction();
	}
}

// FUNCTION: LEGO1 0x10018700
MxResult LegoLoadCacheSoundPresenter::PutData()
{
	ENTER(m_criticalSection);

	if (m_currentTickleState == e_done) {
		m_cacheSound = SoundManager()->GetCacheSoundManager()->ManageSoundEntry(m_cacheSound);
		m_unk0x7c = TRUE;
	}

	m_criticalSection.Leave();
	return SUCCESS;
}
