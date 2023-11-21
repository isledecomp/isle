#include "legophonemepresenter.h"

DECOMP_SIZE_ASSERT(LegoPhonemePresenter, 0x88);

// OFFSET: LEGO1 0x1004e180
LegoPhonemePresenter::LegoPhonemePresenter()
{
	Init();
}

// OFFSET: LEGO1 0x1004e340
LegoPhonemePresenter::~LegoPhonemePresenter()
{
}

// OFFSET: LEGO1 0x1004e3b0
void LegoPhonemePresenter::Init()
{
	m_unk68 = 0;
	m_unk6c = 0;
	m_unk70 = 0;
	m_unk84 = 0;
}
