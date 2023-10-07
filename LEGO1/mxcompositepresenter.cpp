#include "mxcompositepresenter.h"

#include "decomp.h"
#include "mxnotificationmanager.h"

DECOMP_SIZE_ASSERT(MxCompositePresenter, 0x4c);

// OFFSET: LEGO1 0x100b60b0
MxCompositePresenter::MxCompositePresenter()
{
  this->m_unk44 = (undefined4*) malloc(0xc) + 3;
  this->m_unk40 = 0;
  this->m_unk48 = 0;
  NotificationManager()->Register(this);
}

// OFFSET: LEGO1 0x100b6390
MxCompositePresenter::~MxCompositePresenter()
{
  NotificationManager()->Unregister(this);
}
