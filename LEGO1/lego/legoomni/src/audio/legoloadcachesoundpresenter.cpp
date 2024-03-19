#include "legoloadcachesoundpresenter.h"

#include "legocachsound.h"
#include "legosoundmanager.h"
#include "misc.h"
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
	delete[] this->m_unk0x70;
	MxWavePresenter::Destroy(p_fromDestructor);
}

// FUNCTION: LEGO1 0x10018510
void LegoLoadCacheSoundPresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		WaveFormat* header = (WaveFormat*) chunk->GetData();
		m_unk0x78 = 0;

		MxU8* data = new MxU8[header->m_dataSize];
		m_unk0x70 = data;
		m_unk0x74 = data;

		m_cacheSound = new LegoCacheSound;
		memcpy(&m_pcmWaveFormat, &header->m_pcmWaveFormat, sizeof(m_pcmWaveFormat));

		m_subscriber->FreeDataChunk(chunk);
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

// FUNCTION: LEGO1 0x10018700
MxResult LegoLoadCacheSoundPresenter::PutData()
{
	m_criticalSection.Enter();

	if (m_currentTickleState == e_done) {
		m_cacheSound = SoundManager()->GetUnknown0x40()->FUN_1003d290(m_cacheSound);
		m_unk0x7c = 1;
	}

	m_criticalSection.Leave();
	return SUCCESS;
}
