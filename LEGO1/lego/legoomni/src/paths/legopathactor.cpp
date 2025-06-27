#include "legopathactor.h"

#include "define.h"
#include "geom/legoorientededge.h"
#include "legocachesoundmanager.h"
#include "legocameracontroller.h"
#include "legonamedplane.h"
#include "legonavcontroller.h"
#include "legopathboundary.h"
#include "legopathedgecontainer.h"
#include "legosoundmanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "mxutilities.h"
#include "mxvariabletable.h"

#include <mxdebug.h>
#include <vec.h>

DECOMP_SIZE_ASSERT(LegoPathActor, 0x154)
DECOMP_SIZE_ASSERT(LegoPathEdgeContainer, 0x3c)

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
// GLOBAL: BETA10 0x101f1e1c
MxLong g_timeLastHitSoundPlayed = 0;

// FUNCTION: LEGO1 0x1002d700
// FUNCTION: BETA10 0x100ae6e0
LegoPathActor::LegoPathActor()
{
	m_boundary = NULL;
	m_actorTime = 0;
	m_lastTime = 0;
	m_unk0x7c = 0;
	m_userNavFlag = FALSE;
	m_actorState = c_initial;
	m_grec = NULL;
	m_pathController = NULL;
	m_collideBox = FALSE;
	m_unk0x148 = 0;
	m_unk0x14c = 0;
	m_unk0x140 = 0.0099999999f;
	m_unk0x144 = 0.8f;
	m_unk0x150 = 2.0f;
}

// FUNCTION: LEGO1 0x1002d820
// FUNCTION: BETA10 0x100ae80e
LegoPathActor::~LegoPathActor()
{
	if (m_grec) {
		delete m_grec;
	}
}

// FUNCTION: LEGO1 0x1002d8d0
// FUNCTION: BETA10 0x100ae8cd
MxResult LegoPathActor::VTable0x80(const Vector3& p_point1, Vector3& p_point2, Vector3& p_point3, Vector3& p_point4)
{
	Mx3DPointFloat p1, p2, p3;

	p1 = p_point3;
	p1 -= p_point1;
	m_BADuration = p1.LenSquared();

	if (m_BADuration > 0.0f) {
		m_BADuration = sqrtf(m_BADuration);
		p2 = p_point2;
		p3 = p_point4;
		m_unk0x8c.FUN_1009a140(p_point1, p2, p_point3, p3);
		m_BADuration /= 0.001;
		return SUCCESS;
	}
	else {
		MxTrace("Warning: m_BADuration = %g, roi = %s\n", m_BADuration, m_roi->GetName());
		return FAILURE;
	}
}

// FUNCTION: LEGO1 0x1002d9c0
// FUNCTION: BETA10 0x100ae9da
MxResult LegoPathActor::VTable0x88(
	LegoPathBoundary* p_boundary,
	float p_time,
	LegoEdge& p_srcEdge,
	float p_srcScale,
	LegoOrientedEdge& p_destEdge,
	float p_destScale
)
{
	Vector3* v1 = p_srcEdge.CWVertex(*p_boundary);
	Vector3* v2 = p_srcEdge.CCWVertex(*p_boundary);
	Vector3* v3 = p_destEdge.CWVertex(*p_boundary);
	Vector3* v4 = p_destEdge.CCWVertex(*p_boundary);

	Mx3DPointFloat p1, p2, p3, p4, p5;

	p1 = *v2;
	p1 -= *v1;
	p1 *= p_srcScale;
	p1 += *v1;

	p2 = *v4;
	p2 -= *v3;
	p2 *= p_destScale;
	p2 += *v3;

	m_boundary = p_boundary;
	m_destEdge = &p_destEdge;
	m_unk0xe4 = p_destScale;
	m_unk0x7c = 0;
	m_lastTime = p_time;
	m_actorTime = p_time;
	p_destEdge.GetFaceNormal(*p_boundary, p3);

	p4 = p2;
	p4 -= p1;
	p4.Unitize();

	MxMatrix matrix;
	Vector3 pos(matrix[3]);
	Vector3 dir(matrix[2]);
	Vector3 up(matrix[1]);
	Vector3 right(matrix[0]);

	matrix.SetIdentity();
	pos = p1;
	dir = p4;
	up = *m_boundary->GetUp();

	if (!m_cameraFlag || !m_userNavFlag) {
		dir *= -1.0f;
	}

	right.EqualsCross(up, dir);
	m_roi->UpdateTransformationRelativeToParent(matrix);

	if (!m_cameraFlag || !m_userNavFlag) {
		p5.EqualsCross(*p_boundary->GetUp(), p3);
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
		TransformPointOfView();
	}

	m_unk0xec = m_roi->GetLocal2World();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1002de10
// FUNCTION: BETA10 0x100aee61
MxResult LegoPathActor::VTable0x84(
	LegoPathBoundary* p_boundary,
	float p_time,
	Vector3& p_p1,
	Vector3& p_p4,
	LegoOrientedEdge* p_destEdge,
	float p_destScale
)
{
	assert(p_destEdge);

	Vector3* v3 = p_destEdge->CWVertex(*p_boundary);
	Vector3* v4 = p_destEdge->CCWVertex(*p_boundary);

	assert(v3 && v4);

	Mx3DPointFloat p2, p3, p5;

	p2 = *v4;
	p2 -= *v3;
	p2 *= p_destScale;
	p2 += *v3;

	m_boundary = p_boundary;
	m_destEdge = p_destEdge;
	m_unk0xe4 = p_destScale;
	m_unk0x7c = 0;
	m_lastTime = p_time;
	m_actorTime = p_time;
	p_destEdge->GetFaceNormal(*p_boundary, p3);

	MxMatrix matrix;
	Vector3 pos(matrix[3]);
	Vector3 dir(matrix[2]);
	Vector3 up(matrix[1]);
	Vector3 right(matrix[0]);

	matrix.SetIdentity();
	pos = p_p1;
	dir = p_p4;
	up = *m_boundary->GetUp();

	if (!m_cameraFlag || !m_userNavFlag) {
		dir *= -1.0f;
	}

	right.EqualsCross(up, dir);
	m_roi->UpdateTransformationRelativeToParent(matrix);

	if (m_cameraFlag && m_userNavFlag) {
		m_boundary->AddActor(this);
		TransformPointOfView();
	}
	else {
		p5.EqualsCross(*p_boundary->GetUp(), p3);
		p5.Unitize();

		if (VTable0x80(p_p1, p_p4, p2, p5) != SUCCESS) {
			MxTrace("Warning: m_BADuration = %g, roi = %s\n", m_BADuration, m_roi->GetName());
			return FAILURE;
		}

		m_boundary->AddActor(this);
	}

	m_unk0xec = m_roi->GetLocal2World();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1002e100
// FUNCTION: BETA10 0x100b0520
MxS32 LegoPathActor::VTable0x8c(float p_time, Matrix4& p_transform)
{
	if (m_userNavFlag && m_actorState == c_initial) {
		m_lastTime = p_time;

		Mx3DPointFloat p1, p2, p3, p4, p5;
		p5 = Vector3(m_roi->GetWorldDirection());
		p4 = Vector3(m_roi->GetWorldPosition());

		LegoNavController* nav = NavController();
		assert(nav);

		m_worldSpeed = nav->GetLinearVel();

		if (nav->CalculateNewPosDir(p4, p5, p2, p1, m_boundary->GetUp())) {
			Mx3DPointFloat p6;
			p6 = p2;
			MxS32 result = 0;

			m_unk0xe9 = m_boundary->Intersect(m_roi->GetWorldBoundingSphere().Radius(), p4, p2, p3, m_destEdge);
			if (m_unk0xe9 == -1) {
				MxTrace("Intersect returned -1\n");
				return -1;
			}
			else {
				if (m_unk0xe9 != 0) {
					p2 = p3;
				}
			}

			result = VTable0x68(p4, p2, p3);

			if (result > 0) {
				p2 = p4;
				m_unk0xe9 = 0;
				result = 0;
			}
			else {
				m_boundary->CheckAndCallPathTriggers(p4, p2, this);
			}

			LegoPathBoundary* oldBoundary = m_boundary;

			if (m_unk0xe9 != 0) {
				VTable0x9c();

				if (m_boundary == oldBoundary) {
					MxLong time = Timer()->GetTime();

					if (time - g_timeLastHitSoundPlayed > 1000) {
						g_timeLastHitSoundPlayed = time;
						const char* var = VariableTable()->GetVariable(g_strHIT_WALL_SOUND);

						if (var && var[0] != 0) {
							SoundManager()->GetCacheSoundManager()->Play(var, NULL, FALSE);
						}
					}

					m_worldSpeed *= m_unk0x144;
					nav->SetLinearVel(m_worldSpeed);
					Mx3DPointFloat p7(p2);
					p7 -= p6;

					if (p7.Unitize() == 0) {
						float f = sqrt(p1.LenSquared()) * m_unk0x140;
						p7 *= f;
						p1 += p7;
					}
				}
			}

			p_transform.SetIdentity();

			Vector3 right(p_transform[0]);
			Vector3 up(p_transform[1]);
			Vector3 dir(p_transform[2]);
			Vector3 pos(p_transform[3]);

			dir = p1;
			up = *m_boundary->GetUp();
			right.EqualsCross(up, dir);

			MxS32 res = right.Unitize();
			assert(res == 0);

			dir.EqualsCross(right, up);
			pos = p2;
			return result;
		}
		else {
			return -1;
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

		LegoResult r;
		if (m_userNavFlag) {
			r = m_unk0x8c.FUN_1009a1e0(m_unk0x7c / m_BADuration, p_transform, *m_boundary->GetUp(), 0);
		}
		else {
			r = m_unk0x8c.FUN_1009a1e0(m_unk0x7c / m_BADuration, p_transform, *m_boundary->GetUp(), 1);
		}

		assert(r == 0); // SUCCESS

		Vector3 pos1(p_transform[3]);
		Vector3 pos2(m_unk0xec[3]);
		Mx3DPointFloat p1;

		if (VTable0x68(pos2, pos1, p1) > 0) {
			m_lastTime = p_time;
			return 1;
		}
		else {
			m_boundary->CheckAndCallPathTriggers(pos2, pos1, this);
			pos2 = pos1;
		}

		if (m_unk0xe9 != 0) {
			VTable0x9c();
		}
	}
	else {
		return -1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1002e740
// FUNCTION: BETA10 0x100b0f70
void LegoPathActor::VTable0x74(Matrix4& p_transform)
{
	if (m_userNavFlag) {
		m_roi->WrappedSetLocal2WorldWithWorldDataUpdate(p_transform);
		TransformPointOfView();
	}
	else {
		m_roi->WrappedSetLocal2WorldWithWorldDataUpdate(p_transform);
		m_roi->WrappedUpdateWorldData();

		if (m_cameraFlag) {
			TransformPointOfView();
		}
	}
}

// FUNCTION: LEGO1 0x1002e790
// FUNCTION: BETA10 0x100af208
void LegoPathActor::Animate(float p_time)
{
	MxMatrix transform;
	MxU32 b = FALSE;

	while (m_lastTime < p_time) {
		if (m_actorState != c_initial && !VTable0x90(p_time, transform)) {
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
				world->GetCameraController()->RotateZ(DTOR(m_unk0x14c));
			}
		}
	}

	if (b) {
		VTable0x74(transform);
	}
}

// FUNCTION: LEGO1 0x1002e8b0
// FUNCTION: BETA10 0x100af2f7
void LegoPathActor::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoOrientedEdge*& p_edge, float& p_unk0xe4)
{
	assert(m_boundary);
	m_boundary->SwitchBoundary(this, p_boundary, p_edge, p_unk0xe4);
}

// FUNCTION: LEGO1 0x1002e8d0
// FUNCTION: BETA10 0x100b1010
MxU32 LegoPathActor::VTable0x6c(
	LegoPathBoundary* p_boundary,
	Vector3& p_v1,
	Vector3& p_v2,
	float p_f1,
	float p_f2,
	Vector3& p_v3
)
{
	LegoAnimPresenterSet& presenters = p_boundary->GetPresenters();

	for (LegoAnimPresenterSet::iterator itap = presenters.begin(); itap != presenters.end(); itap++) {
		if ((*itap)->VTable0x94(p_v1, p_v2, p_f1, p_f2, p_v3)) {
			return 1;
		}
	}

	LegoPathActorSet& plpas = p_boundary->GetActors();
	LegoPathActorSet lpas(plpas);

	for (LegoPathActorSet::iterator itpa = lpas.begin(); itpa != lpas.end(); itpa++) {
		if (plpas.find(*itpa) != plpas.end()) {
			LegoPathActor* actor = *itpa;

			if (this != actor && !(actor->GetActorState() & LegoPathActor::c_noCollide)) {
				LegoROI* roi = actor->GetROI();

				if (roi != NULL && (roi->GetVisibility() || actor->GetCameraFlag())) {
					if (roi->FUN_100a9410(p_v1, p_v2, p_f1, p_f2, p_v3, m_collideBox && actor->m_collideBox)) {
						HitActor(actor, TRUE);
						actor->HitActor(this, FALSE);
						return 2;
					}
				}
			}
		}
	}

	return 0;
}

inline MxU32 LegoPathActor::FUN_1002edd0(
	list<LegoPathBoundary*>& p_boundaries,
	LegoPathBoundary* p_boundary,
	Vector3& p_v1,
	Vector3& p_v2,
	float p_f1,
	float p_f2,
	Vector3& p_v3,
	MxS32 p_und
)
{
	MxU32 result = VTable0x6c(p_boundary, p_v1, p_v2, p_f1, p_f2, p_v3);

	if (result != 0) {
		return result;
	}

	p_boundaries.push_back(p_boundary);

	if (p_und >= 2) {
		return 0;
	}

	LegoS32 numEdges = p_boundary->GetNumEdges();
	for (MxS32 i = 0; i < numEdges; i++) {
		LegoOrientedEdge* edge = p_boundary->GetEdges()[i];
		LegoPathBoundary* boundary = (LegoPathBoundary*) edge->OtherFace(p_boundary);

		if (boundary != NULL) {
			list<LegoPathBoundary*>::const_iterator it;

			for (it = p_boundaries.begin(); !(it == p_boundaries.end()); it++) {
				if ((*it) == boundary) {
					break;
				}
			}

			if (it == p_boundaries.end()) {
				result = FUN_1002edd0(p_boundaries, boundary, p_v1, p_v2, p_f1, p_f2, p_v3, p_und + 1);

				if (result != 0) {
					return result;
				}
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x1002ebe0
// FUNCTION: BETA10 0x100af35e
MxS32 LegoPathActor::VTable0x68(Vector3& p_v1, Vector3& p_v2, Vector3& p_v3)
{
	assert(m_boundary && m_roi);

	Mx3DPointFloat v2(p_v2);
	v2 -= p_v1;

	float len = v2.LenSquared();

	if (len <= 0.001) {
		return 0;
	}

	len = sqrt((double) len);
	v2 /= len;

	float radius = m_roi->GetWorldBoundingSphere().Radius();
	list<LegoPathBoundary*> boundaries;

	return FUN_1002edd0(boundaries, m_boundary, p_v1, v2, len, radius, p_v3, 0);
}

// FUNCTION: LEGO1 0x1002f020
// FUNCTION: BETA10 0x100af54a
void LegoPathActor::ParseAction(char* p_extra)
{
	LegoActor::ParseAction(p_extra);

	char value[256];
	value[0] = '\0';

	if (KeyValueStringParse(value, g_strPERMIT_NAVIGATE, p_extra)) {
		SetUserNavFlag(TRUE);
		NavController()->ResetMaxLinearVel(m_worldSpeed);
		SetUserActor(this);
	}

	char* token;
	if (KeyValueStringParse(value, g_strPATH, p_extra)) {
		char name[12];

		token = strtok(value, g_parseExtraTokens);
		strcpy(name, token);

		token = strtok(NULL, g_parseExtraTokens);
		MxS32 src = atoi(token);

		token = strtok(NULL, g_parseExtraTokens);
		float srcScale = atof(token);

		token = strtok(NULL, g_parseExtraTokens);
		MxS32 dest = atoi(token);

		token = strtok(NULL, g_parseExtraTokens);
		float destScale = atof(token);

		LegoWorld* world = CurrentWorld();
		if (world != NULL) {
			world->PlaceActor(this, name, src, srcScale, dest, destScale);
		}
	}

	if (KeyValueStringParse(value, g_strCOLLIDEBOX, p_extra)) {
		token = strtok(value, g_parseExtraTokens);
		m_collideBox = atoi(token);
	}
}

// FUNCTION: LEGO1 0x1002f1b0
// FUNCTION: BETA10 0x100af899
MxResult LegoPathActor::VTable0x9c()
{
	Mx3DPointFloat local34;
	Mx3DPointFloat local48;
	MxU32 local1c = 1;
	MxU32 local20 = 1;

	if (m_grec != NULL) {
		if (m_grec->GetBit1()) {
			local1c = 0;
			local20 = 0;

			Mx3DPointFloat vec;
			switch (m_pathController->FUN_1004a240(*m_grec, local34, local48, m_unk0xe4, m_destEdge, m_boundary)) {
			case 0:
			case 1:
				break;
			default:
				return FAILURE;
			}
		}
		else {
			delete m_grec;
			m_grec = NULL;
		}
	}

	if (local1c != 0) {
		SwitchBoundary(m_boundary, m_destEdge, m_unk0xe4);
	}

	if (local20 != 0) {
		Mx3DPointFloat local78;

		Vector3& v1 = *m_destEdge->CWVertex(*m_boundary);
		Vector3& v2 = *m_destEdge->CCWVertex(*m_boundary);

		LERP3(local34, v1, v2, m_unk0xe4);

		m_destEdge->GetFaceNormal(*m_boundary, local78);
		local48.EqualsCross(*m_boundary->GetUp(), local78);
		local48.Unitize();
	}

	Vector3 rightRef(m_unk0xec[0]);
	Vector3 upRef(m_unk0xec[1]);
	Vector3 dirRef(m_unk0xec[2]);

	upRef = *m_boundary->GetUp();

	rightRef.EqualsCross(upRef, dirRef);
	rightRef.Unitize();

	dirRef.EqualsCross(rightRef, upRef);
	dirRef.Unitize();

	Mx3DPointFloat localc0(m_unk0xec[3]);
	Mx3DPointFloat local84(m_unk0xec[2]);
	Mx3DPointFloat local70(local34);

	local70 -= localc0;
	float len = local70.LenSquared();
	if (len >= 0.0f) {
		len = sqrt(len);
		local84 *= len;
		local48 *= len;
	}

	if (!m_userNavFlag) {
		local84 *= -1.0f;
	}

	if (VTable0x80(localc0, local84, local34, local48) != SUCCESS) {
		return FAILURE;
	}

	m_unk0x7c = 0.0f;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1002f650
// FUNCTION: BETA10 0x100afd67
void LegoPathActor::VTable0xa4(MxBool& p_und1, MxS32& p_und2)
{
	switch (GetActorId()) {
	case c_pepper:
		p_und1 = TRUE;
		p_und2 = 2;
		break;
	case c_mama:
		p_und1 = FALSE;
		p_und2 = 1;
		break;
	case c_papa:
		p_und1 = TRUE;
		p_und2 = 1;
		break;
	case c_nick:
	case c_brickster:
		p_und1 = TRUE;
		p_und2 = rand() % p_und2 + 1;
		break;
	case c_laura:
		p_und1 = FALSE;
		p_und2 = 2;
		break;
	default:
		p_und1 = TRUE;
		p_und2 = 1;
		break;
	}
}

// FUNCTION: LEGO1 0x1002f700
// FUNCTION: BETA10 0x100afe4c
void LegoPathActor::VTable0xa8()
{
	m_lastTime = Timer()->GetTime();
	m_roi->SetLocal2World(m_unk0xec);
	m_roi->WrappedUpdateWorldData();

	if (m_userNavFlag) {
		m_roi->WrappedSetLocal2WorldWithWorldDataUpdate(m_unk0xec);
		TransformPointOfView();
	}
}

// FUNCTION: LEGO1 0x1002f770
void LegoPathActor::UpdatePlane(LegoNamedPlane& p_namedPlane)
{
	p_namedPlane.SetName(m_boundary->GetName());
	p_namedPlane.SetPosition(GetWorldPosition());
	p_namedPlane.SetDirection(GetWorldDirection());
	p_namedPlane.SetUp(GetWorldUp());
}

// FUNCTION: LEGO1 0x1002f830
void LegoPathActor::PlaceActor(LegoNamedPlane& p_namedPlane)
{
	if (p_namedPlane.IsPresent()) {
		LegoWorld* world = CurrentWorld();
		world->PlaceActor(this, p_namedPlane.GetName(), 0, 0.5f, 1, 0.5f);
		SetLocation(p_namedPlane.GetPosition(), p_namedPlane.GetDirection(), p_namedPlane.GetUp(), TRUE);
	}
}
