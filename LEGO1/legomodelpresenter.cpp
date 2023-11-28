#include "legomodelpresenter.h"

// 0x100f7ae0
int g_modelPresenterConfig = 1;

// FUNCTION: LEGO1 0x1007f660
void LegoModelPresenter::configureLegoModelPresenter(int param_1)
{
	g_modelPresenterConfig = param_1;
}
