#include "legomodelpresenter.h"

// GLOBAL: LEGO1 0x100f7ae0
int g_modelPresenterConfig = 1;

// FUNCTION: LEGO1 0x1000cca0
void LegoModelPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1007f660
void LegoModelPresenter::configureLegoModelPresenter(MxS32 p_modelPresenterConfig)
{
	g_modelPresenterConfig = p_modelPresenterConfig;
}

// STUB: LEGO1 0x1007f670
void LegoModelPresenter::Destroy(MxBool p_fromDestructor)
{
	// TODO
}

// STUB: LEGO1 0x10080050
void LegoModelPresenter::ReadyTickle()
{
	// TODO
}

// STUB: LEGO1 0x100801b0
void LegoModelPresenter::ParseExtra()
{
	// TODO
}
