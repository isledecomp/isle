#include "mxcompositemediapresenter.h"

#include "legoomni.h"
#include "legovideomanager.h"

DECOMP_SIZE_ASSERT(MxCompositeMediaPresenter, 0x50)

// FUNCTION: LEGO1 0x10073ea0
MxCompositeMediaPresenter::MxCompositeMediaPresenter()
{
	m_unk0x4c = 0;
	m_unk0x4e = 0;
	VideoManager()->AddPresenter(*this);
}

// FUNCTION: LEGO1 0x10074020
MxCompositeMediaPresenter::~MxCompositeMediaPresenter()
{
	VideoManager()->RemovePresenter(*this);
}

// STUB: LEGO1 0x10074090
MxResult MxCompositeMediaPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x100742e0
void MxCompositeMediaPresenter::StartingTickle()
{
	// TODO
}

// STUB: LEGO1 0x10074470
MxResult MxCompositeMediaPresenter::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10074540
MxResult MxCompositeMediaPresenter::PutData()
{
	// TODO
	return SUCCESS;
}
