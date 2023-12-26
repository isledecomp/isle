#include "legoloadcachesoundpresenter.h"

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
