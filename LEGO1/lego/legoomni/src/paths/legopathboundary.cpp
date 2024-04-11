#include "legopathboundary.h"

#include "decomp.h"
#include "legopathactor.h"

DECOMP_SIZE_ASSERT(LegoPathBoundary, 0x74)

// STUB: LEGO1 0x10056a70
LegoPathBoundary::LegoPathBoundary()
{
}

// FUNCTION: LEGO1 0x100573f0
MxResult LegoPathBoundary::AddActor(LegoPathActor* p_actor)
{
	m_unk0x54.insert(p_actor);
	p_actor->SetBoundary(this);
	return SUCCESS;
}
