#include "legopathboundary.h"

#include "decomp.h"
#include "legopathactor.h"

DECOMP_SIZE_ASSERT(LegoPathBoundary, 0x74)

// STUB: LEGO1 0x10056a70
LegoPathBoundary::LegoPathBoundary()
{
	// TODO
}

// STUB: LEGO1 0x10057260
LegoPathBoundary::~LegoPathBoundary()
{
	// TODO
}

// FUNCTION: LEGO1 0x100573f0
MxResult LegoPathBoundary::AddActor(LegoPathActor* p_actor)
{
	m_actors.insert(p_actor);
	p_actor->SetBoundary(this);
	return SUCCESS;
}

// STUB: LEGO1 0x100575b0
void LegoPathBoundary::FUN_100575b0(Vector3& p_point1, Vector3& p_point2, LegoPathActor* p_actor)
{
}

// STUB: LEGO1 0x10057950
MxU32 LegoPathBoundary::Intersect(
	float p_scale,
	Vector3& p_point1,
	Vector3& p_point2,
	Vector3& p_point3,
	LegoEdge*& p_edge
)
{
	return 0;
}
