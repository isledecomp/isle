#include "legopalettepresenter.h"

DECOMP_SIZE_ASSERT(LegoPalettePresenter, 0x68)

// OFFSET: LEGO1 0x10079e50
LegoPalettePresenter::LegoPalettePresenter()
{
	Init();
}

// OFFSET: LEGO1 0x1007a070
LegoPalettePresenter::~LegoPalettePresenter()
{
	Destroy(TRUE);
}

// OFFSET: LEGO1 0x1007a0d0
void LegoPalettePresenter::Init()
{
	m_palette = NULL;
}

// OFFSET: LEGO1 0x1007a0e0
void LegoPalettePresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();
	if (m_palette) {
		delete m_palette;
	}
	Init();
	m_criticalSection.Leave();
	if (!p_fromDestructor) {
		MxVideoPresenter::Destroy(FALSE);
	}
}

// OFFSET: LEGO1 0x1007a120
void LegoPalettePresenter::Destroy()
{
	Destroy(FALSE);
}
