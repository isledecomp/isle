#include "legojetskiraceactor.h"

DECOMP_SIZE_ASSERT(LegoJetskiRaceActor, 0x1a8)

// FUNCTION: LEGO1 0x10080ef0
LegoJetskiRaceActor::LegoJetskiRaceActor()
{
	m_unk0x10 = 0.95f;
	m_unk0x14 = 0.04f;
	m_unk0x18 = 0.5f;
	m_unk0x150 = 1.5f;
}

// STUB: LEGO1 0x10081120
MxS32 LegoJetskiRaceActor::VTable0x1c(LegoPathBoundary* p_boundary, LegoEdge* p_edge)
{
	// TODO
	return 0;
}

// STUB: LEGO1 0x10081550
void LegoJetskiRaceActor::VTable0x70(float p_float)
{
	// TODO
}

// STUB: LEGO1 0x10081fd0
MxU32 LegoJetskiRaceActor::VTable0x6c(
	LegoPathBoundary* p_boundary,
	Vector3& p_v1,
	Vector3& p_v2,
	float p_f1,
	float p_f2,
	Vector3& p_v3
)
{
	// TODO
	return 0;
}
