#include "legoworldpresenter.h"

// GLOBAL: LEGO1 0x100f75d4
undefined4 g_LegoWorldPresenterQuality = 1;

// FUNCTION: LEGO1 0x100665b0
void LegoWorldPresenter::configureLegoWorldPresenter(int p_quality)
{
	g_LegoWorldPresenterQuality = p_quality;
}

// FUNCTION: LEGO1 0x100665c0
LegoWorldPresenter::LegoWorldPresenter()
{
	m_unk50 = 50000;
}

// STUB: LEGO1 0x10066770
LegoWorldPresenter::~LegoWorldPresenter()
{
	// TODO
}
