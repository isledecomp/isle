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

// STUB: LEGO1 0x1002d9c0
void LegoPathActor::VTable0x88()
{
	// TODO
}

// STUB: LEGO1 0x1002de10
void LegoPathActor::VTable0x84()
{
	// TODO
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
void LegoPathActor::ParseAction(char*)
{
	// TODO
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
