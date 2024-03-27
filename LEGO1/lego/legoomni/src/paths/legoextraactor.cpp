#include "legoextraactor.h"

DECOMP_SIZE_ASSERT(LegoExtraActor, 0x1dc)

// GLOBAL: LEGO1 0x10104c18
Mx3DPointFloat g_unk0x10104c18 = Mx3DPointFloat(0.0f, 2.5f, 0.0f);

// FUNCTION: LEGO1 0x1002a500
LegoExtraActor::LegoExtraActor()
{
	m_unk0x70 = 0.0f;
	m_scheduledTime = 0;
	m_unk0x0c = 0;
	m_unk0x0e = 0;
	m_unk0x14 = 0;
	m_unk0x60 = NULL;
	m_unk0x64 = NULL;
	m_unk0x15 = 0;
}

// FUNCTION: LEGO1 0x1002a6b0
LegoExtraActor::~LegoExtraActor()
{
	delete m_unk0x60;
	delete m_unk0x64;
}

// FUNCTION: LEGO1 0x1002a720
MxU32 LegoExtraActor::VTable0x90(float p_time, Matrix4& p_transform)
{
	switch (m_unk0xdc & 0xff) {
	case 0:
	case 1:
		return TRUE;
	case 2:
		m_scheduledTime = p_time + 2000.0f;
		m_unk0xdc = 3;
		m_actorTime += (p_time - m_lastTime) * m_worldSpeed;
		m_lastTime = p_time;
		return FALSE;
	case 3: {
		Vector3 positionRef(p_transform[3]);
		p_transform = m_roi->GetLocal2World();

		if (p_time < m_scheduledTime) {
			Mx3DPointFloat position;
			position = positionRef;
			positionRef.Clear();

			switch (m_axis) {
			case e_posz: {
				p_transform.RotateZ(0.7f);
				break;
			}
			case e_negz: {
				p_transform.RotateZ(-0.7f);
				break;
			}
			case e_posx: {
				p_transform.RotateX(0.7f);
				break;
			}
			case e_negx: {
				p_transform.RotateX(-0.7f);
				break;
			}
			}

			positionRef = position;
			m_actorTime += (p_time - m_lastTime) * m_worldSpeed;
			m_lastTime = p_time;
			VTable0x74(p_transform);
			return FALSE;
		}
		else {
			m_unk0xdc = 0;
			m_scheduledTime = 0.0f;
			((Vector3&) positionRef).Sub(&g_unk0x10104c18); // TODO: Fix call
			m_roi->FUN_100a58f0(p_transform);
			return TRUE;
		}
	}

	default:
		return FALSE;
	}
}

// FUNCTION: LEGO1 0x1002aa90
void LegoExtraActor::VTable0xa4(MxU8& p_und1, MxS32& p_und2)
{
	switch (m_unk0x0c) {
	case 1:
		p_und1 = 1;
		p_und2 = 1;
		return;
	case 2:
		p_und1 = 0;
		p_und2 = 1;
		return;
	default:
		p_und1 = 1;
		p_und2 = rand() % p_und2 + 1;
		return;
	}
}

// FUNCTION: LEGO1 0x1002aae0
MxResult LegoExtraActor::FUN_1002aae0()
{
	LegoPathBoundary* oldEdge = m_boundary;
	Vector3 dir(m_unk0xec[0]);
	Vector3 up(m_unk0xec[2]);
	float scale = -1.0f;
	float* right = m_unk0xec[1];
	up.Mul(scale);
	((Vector3&) dir).EqualsCrossImpl(right, up.GetData());
	if (m_boundary == m_destEdge->m_faceA) {
		m_boundary = (LegoPathBoundary*) m_destEdge->m_faceB;
	}
	else {
		m_boundary = (LegoPathBoundary*) m_destEdge->m_faceA;
	}
	if (!m_boundary) {
		m_boundary = oldEdge;
	}
	LegoPathActor::VTable0x9c();
	return SUCCESS;
}

// STUB: LEGO1 0x1002aba0
MxS32 LegoExtraActor::VTable0x94()
{
	return 0;
}

// STUB: LEGO1 0x1002b290
void LegoExtraActor::VTable0x9c()
{
	// TODO
}

// STUB: LEGO1 0x1002b440
void LegoExtraActor::VTable0x70(float)
{
	// TODO
}

// FUNCTION: LEGO1 0x1002b5d0
void LegoExtraActor::VTable0x74(Matrix4& p_transform)
{
	if (m_unk0x14 == 0) {
		LegoAnimActor::VTable0x74(p_transform);
	}
}

// FUNCTION: LEGO1 0x1002b5f0
void LegoExtraActor::SetWorldSpeed(MxFloat p_worldSpeed)
{
	if (m_curAnim == 0 && p_worldSpeed > 0) {
		VTable0xc4();
	}
	LegoAnimActor::SetWorldSpeed(p_worldSpeed);
}

// STUB: LEGO1 0x1002b630
void LegoExtraActor::VTable0xc4()
{
}

// FUNCTION: LEGO1 0x1002b6f0
void LegoExtraActor::VTable0x68(Mx3DPointFloat& p_point1, Mx3DPointFloat& p_point2, Mx3DPointFloat& p_point3)
{
	LegoPathActor::VTable0x68(p_point1, p_point2, p_point3);
}

// STUB: LEGO1 0x1002b980
void LegoExtraActor::VTable0x6c()
{
}
