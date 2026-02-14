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
	m_transformTime = 0;
	m_traveledDistance = 0;
	m_userNavFlag = FALSE;
	m_actorState = c_initial;
	m_grec = NULL;
	m_pathController = NULL;
	m_collideBox = FALSE;
	m_canRotate = 0;
	m_lastRotationAngle = 0;
	m_wallHitDirectionFactor = 0.0099999999f;
	m_wallHitDampening = 0.8f;
	m_linearRotationRatio = 2.0f;
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
MxResult LegoPathActor::SetSpline(
	const Vector3& p_start,
	Vector3& p_tangentAtStart,
	Vector3& p_end,
	Vector3& p_tangentAtEnd
)
{
	Mx3DPointFloat length, tangentAtStart, tangentAtEnd;

	length = p_end;
	length -= p_start;
	m_BADuration = length.LenSquared();

	if (m_BADuration > 0.0f) {
		m_BADuration = sqrtf(m_BADuration);
		tangentAtStart = p_tangentAtStart;
		tangentAtEnd = p_tangentAtEnd;
		m_spline.SetSpline(p_start, tangentAtStart, p_end, tangentAtEnd);
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
MxResult LegoPathActor::SetTransformAndDestinationFromEdge(
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

	Mx3DPointFloat start, end, destNormal, startDirection, endDirection;

	start = *v2;
	start -= *v1;
	start *= p_srcScale;
	start += *v1;

	end = *v4;
	end -= *v3;
	end *= p_destScale;
	end += *v3;

	m_boundary = p_boundary;
	m_destEdge = &p_destEdge;
	m_destScale = p_destScale;
	m_traveledDistance = 0;
	m_transformTime = p_time;
	m_actorTime = p_time;
	p_destEdge.GetFaceNormal(*p_boundary, destNormal);

	startDirection = end;
	startDirection -= start;
	startDirection.Unitize();

	MxMatrix matrix;
	Vector3 pos(matrix[3]);
	Vector3 dir(matrix[2]);
	Vector3 up(matrix[1]);
	Vector3 right(matrix[0]);

	matrix.SetIdentity();
	pos = start;
	dir = startDirection;
	up = *m_boundary->GetUp();

	if (!m_cameraFlag || !m_userNavFlag) {
		dir *= -1.0f;
	}

	right.EqualsCross(up, dir);
	m_roi->UpdateTransformationRelativeToParent(matrix);

	if (!m_cameraFlag || !m_userNavFlag) {
		endDirection.EqualsCross(*p_boundary->GetUp(), destNormal);
		endDirection.Unitize();

		if (SetSpline(start, startDirection, end, endDirection) == SUCCESS) {
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

	m_local2World = m_roi->GetLocal2World();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1002de10
// FUNCTION: BETA10 0x100aee61
MxResult LegoPathActor::SetTransformAndDestinationFromPoints(
	LegoPathBoundary* p_boundary,
	float p_time,
	Vector3& p_start,
	Vector3& p_direction,
	LegoOrientedEdge* p_destEdge,
	float p_destScale
)
{
	assert(p_destEdge);

	Vector3* v3 = p_destEdge->CWVertex(*p_boundary);
	// LINE: LEGO1 0x1002de35
	Vector3* v4 = p_destEdge->CCWVertex(*p_boundary);

	assert(v3 && v4);

	Mx3DPointFloat end, destNormal, endDirection;

	// LINE: LEGO1 0x1002de8f
	end = *v4;
	end -= *v3;
	end *= p_destScale;
	// LINE: LEGO1 0x1002deae
	end += *v3;

	// LINE: LEGO1 0x1002deba
	m_boundary = p_boundary;
	// LINE: LEGO1 0x1002dece
	m_destEdge = p_destEdge;
	// LINE: LEGO1 0x1002ded4
	m_destScale = p_destScale;
	m_traveledDistance = 0;
	m_transformTime = p_time;
	m_actorTime = p_time;
	// TODO: this one fails to inline
	// LINE: LEGO1 0x1002deed
	p_destEdge->GetFaceNormal(*p_boundary, destNormal);

	MxMatrix matrix;
	Vector3 pos(matrix[3]);
	Vector3 dir(matrix[2]);
	Vector3 up(matrix[1]);
	Vector3 right(matrix[0]);

	matrix.SetIdentity();
	pos = p_start;
	dir = p_direction;
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
		endDirection.EqualsCross(*p_boundary->GetUp(), destNormal);
		endDirection.Unitize();

		if (SetSpline(p_start, p_direction, end, endDirection) != SUCCESS) {
			MxTrace("Warning: m_BADuration = %g, roi = %s\n", m_BADuration, m_roi->GetName());
			return FAILURE;
		}

		m_boundary->AddActor(this);
	}

	m_local2World = m_roi->GetLocal2World();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1002e100
// FUNCTION: BETA10 0x100b0520
MxS32 LegoPathActor::CalculateTransform(float p_time, Matrix4& p_transform)
{
	if (m_userNavFlag && m_actorState == c_initial) {
		m_transformTime = p_time;

		Mx3DPointFloat newDir, newPos, intersectionPoint, pos, dir;
		dir = Vector3(m_roi->GetWorldDirection());
		pos = Vector3(m_roi->GetWorldPosition());

		LegoNavController* nav = NavController();
		assert(nav);

		m_worldSpeed = nav->GetLinearVel();

		if (nav->CalculateNewPosDir(pos, dir, newPos, newDir, m_boundary->GetUp())) {
			Mx3DPointFloat newPosCopy;
			newPosCopy = newPos;
			MxS32 result = 0;

			m_finishedTravel =
				m_boundary
					->Intersect(m_roi->GetWorldBoundingSphere().Radius(), pos, newPos, intersectionPoint, m_destEdge);
			if (m_finishedTravel == -1) {
				MxTrace("Intersect returned -1\n");
				return -1;
			}
			else {
				if (m_finishedTravel != FALSE) {
					newPos = intersectionPoint;
				}
			}

			result = CheckIntersections(pos, newPos, intersectionPoint);

			if (result > 0) {
				newPos = pos;
				m_finishedTravel = FALSE;
				result = 0;
			}
			else {
				m_boundary->CheckAndCallPathTriggers(pos, newPos, this);
			}

			LegoPathBoundary* oldBoundary = m_boundary;

			if (m_finishedTravel != FALSE) {
				CalculateSpline();

				if (m_boundary == oldBoundary) {
					MxLong time = Timer()->GetTime();

					if (time - g_timeLastHitSoundPlayed > 1000) {
						g_timeLastHitSoundPlayed = time;
						const char* var = VariableTable()->GetVariable(g_strHIT_WALL_SOUND);

						if (var && var[0] != 0) {
							SoundManager()->GetCacheSoundManager()->Play(var, NULL, FALSE);
						}
					}

					m_worldSpeed *= m_wallHitDampening;
					nav->SetLinearVel(m_worldSpeed);
					Mx3DPointFloat newPosDelta(newPos);
					newPosDelta -= newPosCopy;

					if (newPosDelta.Unitize() == 0) {
						float f = sqrt(newDir.LenSquared()) * m_wallHitDirectionFactor;
						newPosDelta *= f;
						newDir += newPosDelta;
					}
				}
			}

			p_transform.SetIdentity();

			Vector3 right(p_transform[0]);
			Vector3 up(p_transform[1]);
			Vector3 dir(p_transform[2]);
			Vector3 pos(p_transform[3]);

			dir = newDir;
			up = *m_boundary->GetUp();
			right.EqualsCross(up, dir);

			MxS32 res = right.Unitize();
			assert(res == 0);

			dir.EqualsCross(right, up);
			pos = newPos;
			return result;
		}
		else {
			return -1;
		}
	}
	else if (p_time >= 0 && m_worldSpeed > 0) {
		float endTime = (m_BADuration - m_traveledDistance) / m_worldSpeed + m_transformTime;

		if (endTime < p_time) {
			m_traveledDistance = m_BADuration;
			m_finishedTravel = TRUE;
		}
		else {
			endTime = p_time;
			m_traveledDistance += (endTime - m_transformTime) * m_worldSpeed;
			m_finishedTravel = FALSE;
		}

		m_actorTime += (endTime - m_transformTime) * m_worldSpeed;
		m_transformTime = endTime;
		p_transform.SetIdentity();

		LegoResult r;
		if (m_userNavFlag) {
			r = m_spline.Evaluate(m_traveledDistance / m_BADuration, p_transform, *m_boundary->GetUp(), FALSE);
		}
		else {
			r = m_spline.Evaluate(m_traveledDistance / m_BADuration, p_transform, *m_boundary->GetUp(), TRUE);
		}

		assert(r == 0); // SUCCESS

		Vector3 end(p_transform[3]);
		Vector3 origin(m_local2World[3]);
		Mx3DPointFloat p1;

		if (CheckIntersections(origin, end, p1) > 0) {
			m_transformTime = p_time;
			return 1;
		}
		else {
			m_boundary->CheckAndCallPathTriggers(origin, end, this);
			origin = end;
		}

		if (m_finishedTravel != FALSE) {
			CalculateSpline();
		}
	}
	else {
		return -1;
	}

	return 0;
}

// FUNCTION: LEGO1 0x1002e740
// FUNCTION: BETA10 0x100b0f70
void LegoPathActor::ApplyTransform(Matrix4& p_transform)
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
	MxU32 applyTransform = FALSE;

	while (m_transformTime < p_time) {
		if (m_actorState != c_initial && !StepState(p_time, transform)) {
			return;
		}

		if (CalculateTransform(p_time, transform) != 0) {
			break;
		}

		m_local2World = transform;
		applyTransform = TRUE;

		if (m_finishedTravel != FALSE) {
			break;
		}
	}

	if (m_userNavFlag && m_canRotate) {
		LegoNavController* nav = NavController();
		float vel =
			(nav->GetLinearVel() > 0)
				? -(nav->GetRotationalVel() / (nav->GetMaxLinearVel() * m_linearRotationRatio) * nav->GetLinearVel())
				: 0;

		if ((MxS32) vel != m_lastRotationAngle) {
			m_lastRotationAngle = vel;
			LegoWorld* world = CurrentWorld();

			if (world) {
				world->GetCameraController()->RotateZ(DTOR(m_lastRotationAngle));
			}
		}
	}

	if (applyTransform) {
		ApplyTransform(transform);
	}
}

// FUNCTION: LEGO1 0x1002e8b0
// FUNCTION: BETA10 0x100af2f7
void LegoPathActor::SwitchBoundary(LegoPathBoundary*& p_boundary, LegoOrientedEdge*& p_edge, float& p_scale)
{
	assert(m_boundary);
	m_boundary->SwitchBoundary(this, p_boundary, p_edge, p_scale);
}

// FUNCTION: LEGO1 0x1002e8d0
// FUNCTION: BETA10 0x100b1010
MxU32 LegoPathActor::CheckPresenterAndActorIntersections(
	LegoPathBoundary* p_boundary,
	Vector3& p_rayOrigin,
	Vector3& p_rayDirection,
	float p_rayLength,
	float p_radius,
	Vector3& p_intersectionPoint
)
{
	LegoAnimPresenterSet& presenters = p_boundary->GetPresenters();

	for (LegoAnimPresenterSet::iterator itap = presenters.begin(); itap != presenters.end(); itap++) {
		if ((*itap)->Intersect(p_rayOrigin, p_rayDirection, p_rayLength, p_radius, p_intersectionPoint)) {
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
					if (roi->Intersect(
							p_rayOrigin,
							p_rayDirection,
							p_rayLength,
							p_radius,
							p_intersectionPoint,
							m_collideBox && actor->m_collideBox
						)) {
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

#ifdef BETA10
// FUNCTION: BETA10 0x100af35e
MxS32 LegoPathActor::CheckIntersections(Vector3& p_rayOrigin, Vector3& p_rayEnd, Vector3& p_intersectionPoint)
{
	assert(m_boundary && m_roi);

	Mx3DPointFloat rayDirection(p_rayEnd);
	rayDirection -= p_rayOrigin;

	float len = rayDirection.LenSquared();

	if (len <= 0.001) {
		return 0;
	}

	len = sqrt((double) len);
	rayDirection /= len;

	float radius = m_roi->GetWorldBoundingSphere().Radius();
	LegoPathBoundary* b = m_boundary;
	LegoOrientedEdge* local14 = *m_boundary->GetEdges();
	LegoOrientedEdge* local18 = NULL;

	while (1) {
		assert(b);

		MxU32 result =
			CheckPresenterAndActorIntersections(b, p_rayOrigin, rayDirection, len, radius, p_intersectionPoint);

		if (result != 0) {
			return result;
		}

		if (local18 == NULL) {
			local18 = (LegoOrientedEdge*) local14->GetCounterclockwiseEdge(*m_boundary);
			b = (LegoPathBoundary*) local14->OtherFace(m_boundary);
		}
		else {
			b = NULL;
		}

		while (!b) {
			if (local18 == local14) {
				return 0;
			}

			b = (LegoPathBoundary*) local18->OtherFace(m_boundary);
			local18 = (LegoOrientedEdge*) local18->GetCounterclockwiseEdge(*m_boundary);
		}
	}

	return 0;
}
#else
// FUNCTION: LEGO1 0x1002ebe0
MxS32 LegoPathActor::CheckIntersections(Vector3& p_rayOrigin, Vector3& p_rayEnd, Vector3& p_intersectionPoint)
{
	assert(m_boundary && m_roi);

	Mx3DPointFloat rayDirection(p_rayEnd);
	rayDirection -= p_rayOrigin;

	float len = rayDirection.LenSquared();

	if (len <= 0.001) {
		return 0;
	}

	len = sqrt((double) len);
	rayDirection /= len;

	float radius = m_roi->GetWorldBoundingSphere().Radius();
	list<LegoPathBoundary*> boundaries;
	// This function is inlined once. The recursion calls into the actual function.
	// Matching `CheckIntersectionBothFaces` will likely match `CheckIntersections` as well.
	return CheckIntersectionBothFaces(
		boundaries,
		m_boundary,
		p_rayOrigin,
		rayDirection,
		len,
		radius,
		p_intersectionPoint,
		0
	);
}
#endif

// FUNCTION: LEGO1 0x1002edd0
inline MxU32 LegoPathActor::CheckIntersectionBothFaces(
	list<LegoPathBoundary*>& p_checkedBoundaries,
	LegoPathBoundary* p_boundary,
	Vector3& p_rayOrigin,
	Vector3& p_rayDirection,
	float p_rayLength,
	float p_radius,
	Vector3& p_intersectionPoint,
	MxS32 p_depth
)
{
	MxU32 result = CheckPresenterAndActorIntersections(
		p_boundary,
		p_rayOrigin,
		p_rayDirection,
		p_rayLength,
		p_radius,
		p_intersectionPoint
	);

	if (result != 0) {
		return result;
	}

	p_checkedBoundaries.push_back(p_boundary);

	if (p_depth >= 2) {
		return 0;
	}

	LegoS32 numEdges = p_boundary->GetNumEdges();
	for (MxS32 i = 0; i < numEdges; i++) {
		LegoOrientedEdge* edge = p_boundary->GetEdges()[i];
		// LINE: LEGO1 0x1002ee8c
		LegoPathBoundary* boundary = (LegoPathBoundary*) edge->OtherFace(p_boundary);

		// LINE: LEGO1 0x1002ee9f
		if (boundary != NULL) {
			list<LegoPathBoundary*>::const_iterator it;

			// LINE: LEGO1 0x1002eead
			for (it = p_checkedBoundaries.begin(); !(it == p_checkedBoundaries.end()); it++) {
				// LINE: LEGO1 0x1002eeb3
				if ((*it) == boundary) {
					break;
				}
			}

			// LINE: LEGO1 0x1002eec4
			if (it == p_checkedBoundaries.end()) {
				result = CheckIntersectionBothFaces(
					p_checkedBoundaries,
					boundary,
					p_rayOrigin,
					p_rayDirection,
					p_rayLength,
					p_radius,
					p_intersectionPoint,
					p_depth + 1
				);

				if (result != 0) {
					return result;
				}
			}
		}
	}

	return 0;
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
MxResult LegoPathActor::CalculateSpline()
{
	Mx3DPointFloat targetPosition;
	Mx3DPointFloat endDirection;
	MxU32 noPath1 = TRUE;
	MxU32 noPath2 = TRUE;

	if (m_grec != NULL) {
		if (m_grec->HasPath()) {
			noPath1 = FALSE;
			noPath2 = FALSE;

			Mx3DPointFloat vec;
			switch (m_pathController
						->GetNextPathEdge(*m_grec, targetPosition, endDirection, m_destScale, m_destEdge, m_boundary)) {
			case 0:
			case 1:
				break;
			default:
				assert(0);
				return FAILURE;
			}
		}
		else {
			delete m_grec;
			m_grec = NULL;
		}
	}

	if (noPath1 != FALSE) {
		SwitchBoundary(m_boundary, m_destEdge, m_destScale);
	}

	if (noPath2 != FALSE) {
		Mx3DPointFloat normal;

		assert(m_boundary && m_destEdge);

		Vector3* cw = m_destEdge->CWVertex(*m_boundary);
		Vector3* ccw = m_destEdge->CCWVertex(*m_boundary);

		assert(cw && ccw);

		LERP3(targetPosition, *cw, *ccw, m_destScale);

		m_destEdge->GetFaceNormal(*m_boundary, normal);
		endDirection.EqualsCross(*m_boundary->GetUp(), normal);
		endDirection.Unitize();
	}

	Vector3 rightRef(m_local2World[0]);
	Vector3 upRef(m_local2World[1]);
	Vector3 dirRef(m_local2World[2]);

	upRef = *m_boundary->GetUp();

	rightRef.EqualsCross(upRef, dirRef);
	rightRef.Unitize();

	dirRef.EqualsCross(rightRef, upRef);
	dirRef.Unitize();

	Mx3DPointFloat start(m_local2World[3]);
	Mx3DPointFloat direction(m_local2World[2]);
	Mx3DPointFloat startToTarget(targetPosition);

	startToTarget -= start;
	float len = startToTarget.LenSquared();
	if (len >= 0.0f) {
		len = sqrt(len);
		direction *= len;
		endDirection *= len;
	}

	if (!m_userNavFlag) {
		direction *= -1.0f;
	}

	if (SetSpline(start, direction, targetPosition, endDirection) != SUCCESS) {
		MxTrace("Warning: m_BADuration = %g, roi = %s\n", m_BADuration, m_roi->GetName());
		return FAILURE;
	}

	m_traveledDistance = 0.0f;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1002f650
// FUNCTION: BETA10 0x100afd67
void LegoPathActor::GetWalkingBehavior(MxBool& p_countCounterclockWise, MxS32& p_selectedEdgeIndex)
{
	switch (GetActorId()) {
	case c_pepper:
		p_countCounterclockWise = TRUE;
		p_selectedEdgeIndex = 2;
		break;
	case c_mama:
		p_countCounterclockWise = FALSE;
		p_selectedEdgeIndex = 1;
		break;
	case c_papa:
		p_countCounterclockWise = TRUE;
		p_selectedEdgeIndex = 1;
		break;
	case c_nick:
	case c_brickster:
		p_countCounterclockWise = TRUE;
		p_selectedEdgeIndex = rand() % p_selectedEdgeIndex + 1;
		break;
	case c_laura:
		p_countCounterclockWise = FALSE;
		p_selectedEdgeIndex = 2;
		break;
	default:
		p_countCounterclockWise = TRUE;
		p_selectedEdgeIndex = 1;
		break;
	}
}

// FUNCTION: LEGO1 0x1002f700
// FUNCTION: BETA10 0x100afe4c
void LegoPathActor::ApplyLocal2World()
{
	m_transformTime = Timer()->GetTime();
	m_roi->SetLocal2World(m_local2World);
	m_roi->WrappedUpdateWorldData();

	if (m_userNavFlag) {
		m_roi->WrappedSetLocal2WorldWithWorldDataUpdate(m_local2World);
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
