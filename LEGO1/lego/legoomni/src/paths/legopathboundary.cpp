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

// FUNCTION: LEGO1 0x100574a0
// FUNCTION: BETA10 0x100b156f
MxResult LegoPathBoundary::RemoveActor(LegoPathActor* p_actor)
{
	m_actors.erase(p_actor);
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

// STUB: LEGO1 0x10057fe0
// FUNCTION: BETA10 0x100b2220
MxU32 LegoPathBoundary::FUN_10057fe0(LegoAnimPresenter* p_presenter)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x100586e0
// FUNCTION: BETA10 0x100b22d1
MxU32 LegoPathBoundary::FUN_100586e0(LegoAnimPresenter* p_presenter)
{
	// TODO
	return 0;
}
