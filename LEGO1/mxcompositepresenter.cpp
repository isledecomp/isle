#include "mxcompositepresenter.h"

#include "decomp.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(MxCompositePresenter, 0x4c);

// FUNCTION: LEGO1 0x1000caf0
MxBool MxCompositePresenter::VTable0x64(undefined4 p_unknown)
{
	if (m_compositePresenter)
		return m_compositePresenter->VTable0x64(p_unknown);
	return TRUE;
}

// FUNCTION: LEGO1 0x100b60b0
MxCompositePresenter::MxCompositePresenter()
{
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x100b6390
MxCompositePresenter::~MxCompositePresenter()
{
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x100b67f0 STUB
void MxCompositePresenter::VTable0x58()
{
	// TODO
}

// FUNCTION: LEGO1 0x100b69b0 STUB
void MxCompositePresenter::VTable0x5c()
{
	// TODO
}

// FUNCTION: LEGO1 0x100b6b40 STUB
void MxCompositePresenter::VTable0x60(undefined4 p_unknown)
{
	// TODO
}
