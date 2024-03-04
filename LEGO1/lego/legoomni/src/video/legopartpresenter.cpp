#include "legopartpresenter.h"

#include "legoomni.h"
#include "legovideomanager.h"

// GLOBAL: LEGO1 0x100f7aa0
MxS32 g_partPresenterConfig1 = 1;

// GLOBAL: LEGO1 0x100f7aa4
MxS32 g_partPresenterConfig2 = 100;

// FUNCTION: LEGO1 0x1000cf60
void LegoPartPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1007c990
void LegoPartPresenter::configureLegoPartPresenter(MxS32 p_partPresenterConfig1, MxS32 p_partPresenterConfig2)
{
	g_partPresenterConfig1 = p_partPresenterConfig1;
	g_partPresenterConfig2 = p_partPresenterConfig2;
}

// FUNCTION: LEGO1 0x1007c9b0
MxResult LegoPartPresenter::AddToManager()
{
	VideoManager()->RegisterPresenter(*this);
	return SUCCESS;
}

// STUB: LEGO1 0x1007c9d0
void LegoPartPresenter::Destroy(MxBool p_fromDestructor)
{
	// TODO
}

// STUB: LEGO1 0x1007ca30
MxResult LegoPartPresenter::Read(MxDSChunk& p_chunk)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x1007deb0
void LegoPartPresenter::ReadyTickle()
{
	// TODO
}

// STUB: LEGO1 0x1007df20
void LegoPartPresenter::FUN_1007df20()
{
	// TODO
}
