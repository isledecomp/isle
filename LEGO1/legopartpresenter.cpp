#include "legopartpresenter.h"

// GLOBAL: LEGO1 0x100f7aa0
int g_partPresenterConfig1 = 1;

// GLOBAL: LEGO1 0x100f7aa4
int g_partPresenterConfig2 = 100;

// FUNCTION: LEGO1 0x1007c990
void LegoPartPresenter::configureLegoPartPresenter(MxS32 p_partPresenterConfig1, MxS32 p_partPresenterConfig2)
{
	g_partPresenterConfig1 = p_partPresenterConfig1;
	g_partPresenterConfig2 = p_partPresenterConfig2;
}
