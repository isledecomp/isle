#include "legomodelpresenter.h"

// GLOBAL: LEGO1 0x100f7ae0
int g_modelPresenterConfig = 1;

// FUNCTION: LEGO1 0x1007f660
void LegoModelPresenter::configureLegoModelPresenter(MxS32 p_modelPresenterConfig)
{
	g_modelPresenterConfig = p_modelPresenterConfig;
}
