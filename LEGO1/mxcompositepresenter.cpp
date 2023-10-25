#include "mxcompositepresenter.h"

#include "decomp.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(MxCompositePresenter, 0x4c);

// OFFSET: LEGO1 0x100b60b0
MxCompositePresenter::MxCompositePresenter()
{
	NotificationManager()->Register(this);
}

// OFFSET: LEGO1 0x100b6390
MxCompositePresenter::~MxCompositePresenter()
{
	NotificationManager()->Unregister(this);
}
