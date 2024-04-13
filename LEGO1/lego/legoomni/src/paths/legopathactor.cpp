#include "legopathactor.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(LegoPathActor, 0x154)

// FUNCTION: LEGO1 0x1002d700
LegoPathActor::LegoPathActor()
{
	m_boundary = NULL;
	m_actorTime = 0;
	m_lastTime = 0;
	m_unk0x7c = 0;
	m_userNavFlag = FALSE;
	m_state = 0;
	m_unk0x134 = NULL;
	m_controller = NULL;
	m_unk0xe8 = 0;
	m_unk0x148 = 0;
	m_unk0x14c = 0;
	m_unk0x140 = 0.0099999998f;
	m_unk0x144 = 0.80000001f;
	m_unk0x150 = 2.0f;
}

// STUB: LEGO1 0x1002d820
LegoPathActor::~LegoPathActor()
{
	if (m_unk0x134) {
		delete m_unk0x134;
	}
}

// FUNCTION: LEGO1 0x1002d8d0
MxResult LegoPathActor::VTable0x80(Vector3& p_point1, Vector3& p_point2, Vector3& p_point3, Vector3& p_point4)
{
	Mx3DPointFloat p1, p2, p3;

	p1 = p_point3;
	((Vector3&) p1).Sub(&p_point1);
	m_BADuration = p1.LenSquared();

	if (m_BADuration > 0.0f) {
		m_BADuration = sqrtf(m_BADuration);
		p2 = p_point2;
		p3 = p_point4;
		m_unk0x8c.FUN_1009a140(p_point1, p2, p_point3, p3);
		m_BADuration /= 0.001;
		return SUCCESS;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x1002d9c0
MxResult LegoPathActor::VTable0x88(
	LegoPathBoundary* p_boundary,
	float p_time,
	LegoEdge& p_srcEdge,
	float p_srcScale,
	LegoUnknown100db7f4& p_destEdge,
	float p_destScale
)
{
	Vector3* v1 = p_srcEdge.GetOpposingPoint(p_boundary);
	Vector3* v2 = p_srcEdge.GetPoint(p_boundary);
	Vector3* v3 = p_destEdge.GetOpposingPoint(p_boundary);
	Vector3* v4 = p_destEdge.GetPoint(p_boundary);

	Mx3DPointFloat p1, p2, p3, p4, p5;

	p1 = *v2;
	((Vector3&) p1).Sub(v1);
	((Vector3&) p1).Mul(p_srcScale);
	((Vector3&) p1).Add(v1);

	p2 = *v4;
	((Vector3&) p2).Sub(v3);
	((Vector3&) p2).Mul(p_destScale);
	((Vector3&) p2).Add(v3);

	m_boundary = p_boundary;
	m_destEdge = &p_destEdge;
	m_unk0xe4 = p_destScale;
	m_unk0x7c = 0;
	m_lastTime = p_time;
	m_actorTime = p_time;
	p_destEdge.FUN_1002ddc0(*p_boundary, p3);

	p4 = p2;
	((Vector3&) p4).Sub(&p1);
	p4.Unitize();

	MxMatrix matrix;
	Vector3 pos(matrix[3]);
	Vector3 dir(matrix[2]);
	Vector3 up(matrix[1]);
	Vector3 right(matrix[0]);

	matrix.SetIdentity();
	pos = p1;
	dir = p4;
	up = *m_boundary->GetUnknown0x14();

	if (!m_cameraFlag || !m_userNavFlag) {
		((Vector3&) dir).Mul(-1.0f);
	}

	right.EqualsCross(&up, &dir);
	m_roi->FUN_100a46b0(matrix);

	if (!m_cameraFlag || !m_userNavFlag) {
		p5.EqualsCross(p_boundary->GetUnknown0x14(), &p3);
		p5.Unitize();

		if (VTable0x80(p1, p4, p2, p5) == SUCCESS) {
			m_boundary->AddActor(this);
		}
		else {
			return FAILURE;
		}
	}
	else {
		m_boundary->AddActor(this);
		FUN_10010c30();
	}

	m_unk0xec = m_roi->GetLocal2World();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1002de10
MxResult LegoPathActor::VTable0x84(
	LegoPathBoundary* p_boundary,
	float p_time,
	Vector3& p_p1,
	Vector3& p_p4,
	LegoUnknown100db7f4& p_destEdge,
	float p_destScale
)
{
	Vector3* v3 = p_destEdge.GetOpposingPoint(p_boundary);
	Vector3* v4 = p_destEdge.GetPoint(p_boundary);

	Mx3DPointFloat p2, p3, p5;

	p2 = *v4;
	((Vector3&) p2).Sub(v3);
	((Vector3&) p2).Mul(p_destScale);
	((Vector3&) p2).Add(v3);

	m_boundary = p_boundary;
	m_destEdge = &p_destEdge;
	m_unk0xe4 = p_destScale;
	m_unk0x7c = 0;
	m_lastTime = p_time;
	m_actorTime = p_time;
	p_destEdge.FUN_1002ddc0(*p_boundary, p3);

	MxMatrix matrix;
	Vector3 pos(matrix[3]);
	Vector3 dir(matrix[2]);
	Vector3 up(matrix[1]);
	Vector3 right(matrix[0]);

	matrix.SetIdentity();
	pos = p_p1;
	dir = p_p4;
	up = *m_boundary->GetUnknown0x14();

	if (!m_cameraFlag || !m_userNavFlag) {
		((Vector3&) dir).Mul(-1.0f);
	}

	right.EqualsCross(&up, &dir);
	m_roi->FUN_100a46b0(matrix);

	if (!m_cameraFlag || !m_userNavFlag) {
		p5.EqualsCross(p_boundary->GetUnknown0x14(), &p3);
		p5.Unitize();

		if (VTable0x80(p_p1, p_p4, p2, p5) == SUCCESS) {
			m_boundary->AddActor(this);
		}
		else {
			return FAILURE;
		}
	}
	else {
		m_boundary->AddActor(this);
		FUN_10010c30();
	}

	m_unk0xec = m_roi->GetLocal2World();
	return SUCCESS;
}

// STUB: LEGO1 0x1002e100
void LegoPathActor::VTable0x8c()
{
	// TODO
}

// STUB: LEGO1 0x1002e740
void LegoPathActor::VTable0x74(Matrix4& p_transform)
{
	// TODO
}

// STUB: LEGO1 0x1002e790
void LegoPathActor::VTable0x70(float)
{
	// TODO
}

// STUB: LEGO1 0x1002e8b0
void LegoPathActor::VTable0x98()
{
	// TODO
}

// STUB: LEGO1 0x1002e8d0
void LegoPathActor::VTable0x6c()
{
	// TODO
}

// STUB: LEGO1 0x1002ebe0
void LegoPathActor::VTable0x68(Mx3DPointFloat&, Mx3DPointFloat&, Mx3DPointFloat&)
{
	// TODO
}

// STUB: LEGO1 0x1002f020
void LegoPathActor::ParseAction(char* p_extra)
{
	LegoActor::ParseAction(p_extra);
}

// STUB: LEGO1 0x1002f1b0
MxResult LegoPathActor::WaitForAnimation()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x1002f650
void LegoPathActor::VTable0xa4(MxU8&, MxS32&)
{
	// TODO
}

// STUB: LEGO1 0x1002f700
void LegoPathActor::VTable0xa8()
{
	// TODO
}
