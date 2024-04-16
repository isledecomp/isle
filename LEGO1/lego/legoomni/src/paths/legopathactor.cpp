#include "legopathactor.h"

#include "legonavcontroller.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxtimer.h"

#include <vec.h>

DECOMP_SIZE_ASSERT(LegoPathActor, 0x154)

#ifndef M_PI
#define M_PI 3.1416
#endif
#ifdef DTOR
#undef DTOR
#endif
#define DTOR(angle) ((angle) * M_PI / 180.)

// GLOBAL: LEGO1 0x100f3304
// STRING: LEGO1 0x100f32f4
const char* g_strHIT_WALL_SOUND = "HIT_WALL_SOUND";

// GLOBAL: LEGO1 0x100f3308
MxLong g_unk0x100f3308 = 0;

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

// FUNCTION: LEGO1 0x1002e100
MxS32 LegoPathActor::VTable0x8c(float p_time, Matrix4& p_transform)
{
	if (m_userNavFlag && m_state == 0) {
		m_lastTime = p_time;

		Mx3DPointFloat p1, p2, p3, p4, p5;
		p5 = Vector3(m_roi->GetWorldDirection());
		p4 = Vector3(m_roi->GetWorldPosition());

		LegoNavController* nav = NavController();
		m_worldSpeed = nav->GetLinearVel();

		if (nav->CalculateNewPosDir(p4, p5, p2, p1, m_boundary->GetUnknown0x14())) {
			Mx3DPointFloat p6;
			p6 = p2;

			m_unk0xe9 = m_boundary->Intersect(m_roi->GetWorldBoundingSphere().Radius(), p4, p2, p3, m_destEdge);
			if (m_unk0xe9 == -1) {
				return -1;
			}

			if (m_unk0xe9 != 0) {
				p2 = p3;
			}

			MxS32 result = VTable0x68(p4, p2, p3);

			if (result > 0) {
				p2 = p4;
				m_unk0xe9 = 0;
				result = 0;
			}
			else {
				m_boundary->FUN_100575b0(p4, p2, this);
			}

			LegoPathBoundary* oldBoundary = m_boundary;

			if (m_unk0xe9 != 0) {
				WaitForAnimation();

				if (m_boundary == oldBoundary) {
					MxLong time = Timer()->GetTime();

					if (time - g_unk0x100f3308 > 1000) {
						g_unk0x100f3308 = time;
						const char* var = VariableTable()->GetVariable(g_strHIT_WALL_SOUND);

						if (var && var[0] != 0) {
							SoundManager()->GetCacheSoundManager()->FUN_1003dae0(var, NULL, FALSE);
						}
					}

					m_worldSpeed *= m_unk0x144;
					nav->SetLinearVel(m_worldSpeed);
					Mx3DPointFloat p7(p2);
					((Vector3&) p7).Sub(&p6);

					if (p7.Unitize() == 0) {
						float f = sqrt(p1.LenSquared()) * m_unk0x140;
						((Vector3&) p7).Mul(f);
						((Vector3&) p1).Add(&p7);
					}
				}
			}

			p_transform.SetIdentity();

			Vector3 right(p_transform[0]);
			Vector3 up(p_transform[1]);
			Vector3 dir(p_transform[2]);
			Vector3 pos(p_transform[3]);

			dir = p1;
			up = *m_boundary->GetUnknown0x14();
			right.EqualsCross(&up, &dir);
			right.Unitize();
			dir.EqualsCross(&right, &up);
			pos = p2;
			return result;
		}
	}
	else if (p_time >= 0 && m_worldSpeed > 0) {
		float f = (m_BADuration - m_unk0x7c) / m_worldSpeed + m_lastTime;

		if (f < p_time) {
			m_unk0x7c = m_BADuration;
			m_unk0xe9 = 1;
		}
		else {
			f = p_time;
			m_unk0x7c += (f - m_lastTime) * m_worldSpeed;
			m_unk0xe9 = 0;
		}

		m_actorTime += (f - m_lastTime) * m_worldSpeed;
		m_lastTime = f;
		p_transform.SetIdentity();

		if (m_userNavFlag) {
			m_unk0x8c.FUN_1009a1e0(m_unk0x7c / m_BADuration, p_transform, *m_boundary->GetUnknown0x14(), 0);
		}
		else {
			m_unk0x8c.FUN_1009a1e0(m_unk0x7c / m_BADuration, p_transform, *m_boundary->GetUnknown0x14(), 1);
		}

		Vector3 pos1(p_transform[3]);
		Vector3 pos2(m_unk0xec[3]);
		Mx3DPointFloat p1;

		if (VTable0x68(pos2, pos1, p1) > 0) {
			m_lastTime = p_time;
			return 1;
		}
		else {
			m_boundary->FUN_100575b0(pos2, pos1, this);
			pos2 = pos1;

			if (m_unk0xe9 != 0) {
				WaitForAnimation();
			}

			return 0;
		}
	}

	return -1;
}

// FUNCTION: LEGO1 0x1002e740
void LegoPathActor::VTable0x74(Matrix4& p_transform)
{
	if (m_userNavFlag) {
		m_roi->WrappedSetLocalTransform(p_transform);
		FUN_10010c30();
	}
	else {
		m_roi->WrappedSetLocalTransform(p_transform);
		m_roi->VTable0x14();

		if (m_cameraFlag) {
			FUN_10010c30();
		}
	}
}

// FUNCTION: LEGO1 0x1002e790
void LegoPathActor::VTable0x70(float p_time)
{
	MxMatrix transform;
	MxU32 b = FALSE;

	while (m_lastTime < p_time) {
		if (m_state != 0 && !VTable0x90(p_time, transform)) {
			return;
		}

		if (VTable0x8c(p_time, transform) != 0) {
			break;
		}

		m_unk0xec = transform;
		b = TRUE;

		if (m_unk0xe9 != 0) {
			break;
		}
	}

	if (m_userNavFlag && m_unk0x148) {
		LegoNavController* nav = NavController();
		float vel = (nav->GetLinearVel() > 0)
						? -(nav->GetRotationalVel() / (nav->GetMaxLinearVel() * m_unk0x150) * nav->GetLinearVel())
						: 0;

		if ((MxS32) vel != m_unk0x14c) {
			m_unk0x14c = vel;
			LegoWorld* world = CurrentWorld();

			if (world) {
				world->GetCamera()->FUN_10012290(DTOR(m_unk0x14c));
			}
		}
	}

	if (b) {
		VTable0x74(transform);
	}
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
MxS32 LegoPathActor::VTable0x68(Vector3&, Vector3&, Vector3&)
{
	// TODO
	return 0;
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
