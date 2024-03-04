#include "legotexturepresenter.h"

#include "legoomni.h"
#include "legovideomanager.h"
#include "mxcompositepresenter.h"

DECOMP_SIZE_ASSERT(LegoTexturePresenter, 0x54)

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

// STUB: LEGO1 0x1004ebd0
MxResult LegoTexturePresenter::Read(MxDSChunk& p_chunk)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x1004f290
void LegoTexturePresenter::FUN_1004f290()
{
	// TODO
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
		SetTickleState(e_idle);
		return;
	}

	MxMediaPresenter::DoneTickle();
}
