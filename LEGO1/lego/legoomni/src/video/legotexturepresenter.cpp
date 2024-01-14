#include "legotexturepresenter.h"

#include "legoomni.h"
#include "legovideomanager.h"
#include "mxcompositepresenter.h"

// FUNCTION: LEGO1 0x1004eb40
LegoTexturePresenter::~LegoTexturePresenter()
{
	VideoManager()->UnregisterPresenter(*this);
}

// FUNCTION: LEGO1 0x1004ebb0
MxResult LegoTexturePresenter::AddToManager()
{
	VideoManager()->RegisterPresenter(*this);
	return SUCCESS;
}

// STUB: LEGO1 0x1004fc60
MxResult LegoTexturePresenter::PutData()
{
	// TODO
	return FAILURE;
}

// FUNCTION: LEGO1 0x1004fcb0
void LegoTexturePresenter::DoneTickle()
{
	if (this->m_compositePresenter && !this->m_compositePresenter->VTable0x64(2)) {
		SetTickleState(TickleState_Idle);
		return;
	}

	MxMediaPresenter::DoneTickle();
}
