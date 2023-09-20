#include "mxdsparallelaction.h"

DECOMP_SIZE_ASSERT(MxDSParallelAction, 0x9c)

// OFFSET: LEGO1 0x100cae80
MxDSParallelAction::MxDSParallelAction()
{
  this->SetType(MxDSType_ParallelAction);
}

// OFFSET: LEGO1 0x100cb040
MxDSParallelAction::~MxDSParallelAction()
{
}
