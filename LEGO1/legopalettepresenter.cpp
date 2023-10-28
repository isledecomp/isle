#include "legopalettepresenter.h"

DECOMP_SIZE_ASSERT(LegoPalettePresenter, 0x68)

// OFFSET: LEGO1 0x10079e50
LegoPalettePresenter::LegoPalettePresenter()
{
	Init();
}

// OFFSET: LEGO1 0x1007a070 STUB
LegoPalettePresenter::~LegoPalettePresenter()
{
	// TODO
}

// OFFSET: LEGO1 0x1007a0d0
void LegoPalettePresenter::Init()
{
	this->m_unk64 = 0;
}
