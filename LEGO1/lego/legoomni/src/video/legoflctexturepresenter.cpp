#include "legoflctexturepresenter.h"

DECOMP_SIZE_ASSERT(LegoFlcTexturePresenter, 0x70)

// FUNCTION: LEGO1 0x1005de80
LegoFlcTexturePresenter::LegoFlcTexturePresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x1005df70
void LegoFlcTexturePresenter::Init()
{
	this->m_unk0x68 = 0;
	this->m_unk0x6c = 0;
}
