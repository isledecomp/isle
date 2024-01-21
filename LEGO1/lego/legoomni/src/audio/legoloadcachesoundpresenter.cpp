#include "legoloadcachesoundpresenter.h"

#include "legocachesound.h"
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
	this->m_unk0x70 = NULL;
	this->m_unk0x78 = 0;
	this->m_unk0x7c = 0;
}

// FUNCTION: LEGO1 0x100184f0
void LegoLoadCacheSoundPresenter::Destroy(MxBool p_fromDestructor)
{
	delete this->m_unk0x70;
	MxWavePresenter::Destroy(p_fromDestructor);
}

// FUNCTION: LEGO1 0x10018510
void LegoLoadCacheSoundPresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();
	if (chunk) {
		WaveFormat* header = (WaveFormat*) chunk->GetData();
		m_unk0x78 = 0;
		undefined4* buf = new undefined4[header->m_dataSize];
		m_unk0x70 = buf;
		m_unk0x74 = buf;
		m_cacheSound = new LegoCacheSound();

		// parse header
		m_waveFormat2 = header->m_waveFormatEx.wFormatTag; // TODO: Match
		m_samplesPerSec = header->m_waveFormatEx.nSamplesPerSec;
		m_avgBytesPerSec = header->m_waveFormatEx.nAvgBytesPerSec;
		m_blockalign = header->m_waveFormatEx.nBlockAlign;

		m_subscriber->DestroyChunk(chunk);
		ProgressTickleState(e_streaming);
	}
}

// STUB: LEGO1 0x100185f0
void LegoLoadCacheSoundPresenter::StreamingTickle()
{
	// TODO
	EndAction();
}

// FUNCTION: LEGO1 0x100186f0
void LegoLoadCacheSoundPresenter::DoneTickle()
{
	if (m_unk0x7c != 0) {
		EndAction();
	}
}

// STUB: LEGO1 0x10018700
MxResult LegoLoadCacheSoundPresenter::PutData()
{
	// TODO
	return SUCCESS;
}
