#include "legopartpresenter.h"

// GLOBAL: LEGO1 0x100f7aa0
int g_partPresenterConfig1 = 1;

// GLOBAL: LEGO1 0x100f7aa4
int g_partPresenterConfig2 = 100;

// FUNCTION: LEGO1 0x1007c990
void LegoPartPresenter::configureLegoPartPresenter(int param_1, int param_2)
{
	g_partPresenterConfig1 = param_1;
	g_partPresenterConfig2 = param_2;
}
