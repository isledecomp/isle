#include "legoworldpresenter.h"

// GLOBAL: LEGO1 0x100f75d4
undefined4 g_legoWorldPresenterQuality = 1;

// FUNCTION: LEGO1 0x100665b0
void LegoWorldPresenter::configureLegoWorldPresenter(MxS32 p_legoWorldPresenterQuality)
{
	g_legoWorldPresenterQuality = p_legoWorldPresenterQuality;
}

// FUNCTION: LEGO1 0x100665c0
LegoWorldPresenter::LegoWorldPresenter()
{
	m_unk0x50 = 50000;
}

// STUB: LEGO1 0x10066770
LegoWorldPresenter::~LegoWorldPresenter()
{
	// TODO
}
