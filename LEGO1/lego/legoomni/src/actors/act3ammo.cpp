#include "act3ammo.h"

#include "act3.h"
#include "act3actors.h"
#include "legocachesoundmanager.h"
#include "legocharactermanager.h"
#include "legopathboundary.h"
#include "legopathcontroller.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "roi/legoroi.h"

#include <assert.h>
#include <stdio.h>

DECOMP_SIZE_ASSERT(Act3Ammo, 0x1a0)

// Initialized at LEGO1 0x100537c0
// GLOBAL: LEGO1 0x10104f08
Mx3DPointFloat Act3Ammo::g_hitTranslation = Mx3DPointFloat(0.0, 5.0, 0.0);

// FUNCTION: LEGO1 0x100537f0
// FUNCTION: BETA10 0x1001d648
Act3Ammo::Act3Ammo()
{
	m_ammoFlag = 0;
	m_world = NULL;
}

// FUNCTION: LEGO1 0x100538a0
// FUNCTION: BETA10 0x1001d6e7
Act3Ammo::~Act3Ammo()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x10053900
// FUNCTION: BETA10 0x1001d759
void Act3Ammo::Destroy(MxBool p_fromDestructor)
{
	if (!p_fromDestructor) {
		assert(0);
	}
	else if (m_roi != NULL) {
		CharacterManager()->ReleaseActor(m_roi->GetName());
		m_roi = NULL;
	}
}

// FUNCTION: LEGO1 0x10053930
// FUNCTION: BETA10 0x1001d7d0
MxResult Act3Ammo::Remove()
{
	assert(IsValid());
	assert(m_roi && m_pathController);

	CharacterManager()->ReleaseActor(m_roi->GetName());
	m_roi = NULL;

	if (m_boundary != NULL) {
		m_boundary->RemoveActor(this);
	}

	m_pathController->RemoveActor(this);
	m_ammoFlag = 0;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10053980
// FUNCTION: BETA10 0x1001d8b3
MxResult Act3Ammo::Create(Act3* p_world, MxU32 p_isPizza, MxS32 p_index)
{
#ifdef BETA10
	assert(m_ammoFlag);
#endif
	char name[12];

	if (p_isPizza) {
		sprintf(name, "pammo%d", p_index);
		m_roi = CharacterManager()->CreateAutoROI(name, "pizpie", FALSE);
		m_roi->SetVisibility(TRUE);

		BoundingSphere sphere;

		sphere.Center()[0] = sphere.Center()[1] = sphere.Center()[2] = 0.0f;
		sphere.Radius() = m_roi->GetBoundingSphere().Radius() * 2.0f;
		m_roi->SetBoundingSphere(sphere);

		m_ammoFlag = c_pizza;
		assert(m_roi);
	}
	else {
		sprintf(name, "dammo%d", p_index);
		m_roi = CharacterManager()->CreateAutoROI(name, "donut", FALSE);
		m_roi->SetVisibility(TRUE);

		BoundingSphere sphere;

		sphere.Center()[0] = sphere.Center()[1] = sphere.Center()[2] = 0.0f;
		sphere.Radius() = m_roi->GetBoundingSphere().Radius() * 5.0f;
		m_roi->SetBoundingSphere(sphere);

		m_ammoFlag = c_donut;
		assert(m_roi);
	}

	m_world = p_world;
	SetValid(TRUE);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10053b40
// FUNCTION: BETA10 0x1001db2a
MxResult Act3Ammo::CalculateArc(const Vector3& p_srcLoc, const Vector3& p_srcDir, const Vector3& p_srcUp)
{
	assert(p_srcDir[1] != 0);

	MxFloat yRatioLocDir = -(p_srcLoc[1] / p_srcDir[1]);
	Mx3DPointFloat groundPoint(p_srcDir);
	Mx3DPointFloat negNormalUp;

	groundPoint *= yRatioLocDir;
	groundPoint += p_srcLoc;

	negNormalUp[0] = negNormalUp[2] = 0.0f;
	negNormalUp[1] = -1.0f;

	m_coefficients[1] = p_srcUp;
	m_coefficients[2] = p_srcLoc;

	Mx3DPointFloat upRelative(negNormalUp);
	upRelative -= m_coefficients[1];

	for (MxS32 i = 0; i < 3; i++) {
		if (groundPoint[0] == p_srcLoc[0]) {
			return FAILURE;
		}

		m_coefficients[0][i] = (upRelative[i] * upRelative[i] + upRelative[i] * m_coefficients[1][i] * 2.0f) /
							   ((groundPoint[i] - p_srcLoc[i]) * 4.0f);
	}

	assert(m_coefficients[0][0] > 0.000001 || m_coefficients[0][0] < -0.000001);

	m_apexParameter = upRelative[0] / (m_coefficients[0][0] * 2.0f);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10053cb0
// FUNCTION: BETA10 0x1001ddf4
MxResult Act3Ammo::Shoot(LegoPathController* p_p, LegoPathBoundary* p_boundary, MxFloat p_apexParameter)
{
	assert(p_p);
	assert(IsValid());

	if (IsPizza()) {
		assert(SoundManager()->GetCacheSoundManager());
		SoundManager()->GetCacheSoundManager()->Play("shootpz", NULL, FALSE);
	}
	else {
		assert(SoundManager()->GetCacheSoundManager());
		SoundManager()->GetCacheSoundManager()->Play("shootdn", NULL, FALSE);
	}

	m_pathController = p_p;
	m_boundary = p_boundary;
	m_BADuration = 10000.0f;
	m_apexParameter = p_apexParameter;
	m_traveledDistance = 0.0f;
	m_transformTime = -1.0f;
	m_actorState = c_ready;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10053d30
// FUNCTION: BETA10 0x1001df73
MxResult Act3Ammo::Shoot(LegoPathController* p_p, MxFloat p_apexParameter)
{
	assert(p_p);
	assert(IsValid());

	SetShootWithoutBoundary(TRUE);

	if (IsPizza()) {
		assert(SoundManager()->GetCacheSoundManager());
		SoundManager()->GetCacheSoundManager()->Play("shootpz", NULL, FALSE);
	}
	else {
		assert(SoundManager()->GetCacheSoundManager());
		SoundManager()->GetCacheSoundManager()->Play("shootdn", NULL, FALSE);
	}

	m_pathController = p_p;
	m_BADuration = 10000.0f;
	m_apexParameter = p_apexParameter;
	m_traveledDistance = 0.0f;
	m_transformTime = -1.0f;
	m_actorState = c_ready;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10053db0
// FUNCTION: BETA10 0x1001e0f0
MxResult Act3Ammo::CalculateTransformOnCurve(float p_curveParameter, Matrix4& p_transform)
{
	float curveParameterSquare = p_curveParameter * p_curveParameter;

	Vector3 right(p_transform[0]);
	Vector3 up(p_transform[1]);
	Vector3 dir(p_transform[2]);
	Vector3 pos(p_transform[3]);
	Mx3DPointFloat sndCoeff;

	sndCoeff = m_coefficients[1];
	sndCoeff *= p_curveParameter;
	pos = m_coefficients[0];
	pos *= curveParameterSquare;
	pos += sndCoeff;
	pos += m_coefficients[2];
	dir = m_coefficients[0];
	dir *= 2.0f;
	dir *= p_curveParameter;
	dir += m_coefficients[1];
	dir *= -1.0f;

	if (dir.Unitize() != 0) {
		assert(0);
		return FAILURE;
	}

	right[1] = right[2] = 0.0f;
	right[0] = 1.0f;
	up.EqualsCross(dir, right);

	if (up.Unitize() != 0) {
		right[0] = right[1] = 0.0f;
		right[2] = 1.0f;
		up.EqualsCross(dir, right);

		if (up.Unitize() != 0) {
			assert(0);
			return FAILURE;
		}
	}

	right.EqualsCross(up, dir);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10054050
// FUNCTION: BETA10 0x1001e362
void Act3Ammo::Animate(float p_time)
{
	assert(IsValid());

	switch (m_actorState & c_maxState) {
	case c_initial:
	case c_ready:
		break;
	case c_hit:
		m_rotateTimeout = p_time + 2000.0f;
		m_actorState = c_hitAnimation;
		return;
	case c_hitAnimation:
		MxMatrix transform;
		Vector3 positionRef(transform[3]);

		transform = m_roi->GetLocal2World();

		if (m_rotateTimeout > p_time) {
			Mx3DPointFloat position;

			position = positionRef;
			positionRef.Clear();
			transform.RotateX(0.6);
			positionRef = position;
			m_roi->SetLocal2World(transform);
			m_roi->WrappedUpdateWorldData();
			return;
		}
		else {
			m_actorState = c_initial;
			m_rotateTimeout = 0;

			positionRef -= g_hitTranslation;
			m_roi->SetLocal2World(transform);
			m_roi->WrappedUpdateWorldData();
			return;
		}
	}

	if (m_worldSpeed <= 0.0f) {
		return;
	}

	if (m_transformTime < 0.0f) {
		m_transformTime = p_time;
		m_traveledDistance = 0.0f;
	}

	MxMatrix transform;
	MxMatrix additionalTransform;

	float f = (m_BADuration - m_traveledDistance) / m_worldSpeed + m_transformTime;

	undefined4 unused1 = 0;
	undefined4 unused2 = 0;
	MxU32 annihilated = FALSE;
	MxU32 reachedTarget = FALSE;

	if (f >= p_time) {
		m_actorTime = (p_time - m_transformTime) * m_worldSpeed + m_actorTime;
		m_traveledDistance = (p_time - m_transformTime) * m_worldSpeed + m_traveledDistance;
		m_transformTime = p_time;
	}
	else {
		reachedTarget = TRUE;
		m_traveledDistance = m_BADuration;
		m_transformTime = p_time;
	}

	transform.SetIdentity();

	MxResult r = CalculateTransformOnCurve((m_traveledDistance / m_BADuration) * m_apexParameter, transform);
	assert(r == 0); // SUCCESS

	additionalTransform.SetIdentity();

	if (IsPizza()) {
		additionalTransform.Scale(2.0f, 2.0f, 2.0f);
	}
	else {
		additionalTransform.Scale(5.0f, 5.0f, 5.0f);
	}

	if (reachedTarget) {
		if (m_boundary != NULL) {
			Vector3 right(transform[0]);
			Vector3 up(transform[1]);
			Vector3 dir(transform[2]);

			if (IsPizza()) {
				up = *m_boundary->GetUp();
				right[0] = 1.0f;
				right[1] = right[2] = 0.0f;
				dir.EqualsCross(right, up);
				dir.Unitize();
				right.EqualsCross(up, dir);
			}
			else {
				right = *m_boundary->GetUp();
				up[0] = 1.0f;
				up[1] = up[2] = 0.0f;
				dir.EqualsCross(right, up);
				dir.Unitize();
				up.EqualsCross(dir, right);
			}
		}

		m_actorState = c_initial;
	}
	else {
		additionalTransform.RotateX(m_actorTime / 10.0f);
		additionalTransform.RotateY(m_actorTime / 6.0f);
	}

	MxMatrix transformCopy(transform);
	transform.Product(additionalTransform, transformCopy);
	m_roi->SetLocal2World(transform);
	m_roi->WrappedUpdateWorldData();

	if (m_BADuration <= m_traveledDistance) {
		m_worldSpeed = 0.0f;
	}

	Vector3 position(transform[3]);

	if (reachedTarget) {
		if (IsShootWithoutBoundary()) {
			if (IsPizza()) {
				m_world->RemovePizza(*this);
				m_world->TriggerHitSound(2);
			}
			else {
				m_world->RemoveDonut(*this);
				m_world->TriggerHitSound(4);
			}

			return;
		}
		else {
			if (IsPizza()) {
				assert(SoundManager()->GetCacheSoundManager());
				SoundManager()->GetCacheSoundManager()->Play("stickpz", NULL, FALSE);
			}
			else {
				assert(SoundManager()->GetCacheSoundManager());
				SoundManager()->GetCacheSoundManager()->Play("stickdn", NULL, FALSE);
			}
		}

		LegoPathActorSet& plpas = m_boundary->GetActors();
		LegoPathActorSet lpas(plpas);

		for (LegoPathActorSet::iterator itpa = lpas.begin(); itpa != lpas.end(); itpa++) {
			if (plpas.find(*itpa) == plpas.end()) {
				continue;
			}

			if (this == *itpa) {
				continue;
			}

			LegoROI* r = (*itpa)->GetROI();
			assert(r);

			if (!strncmp(r->GetName(), "pammo", 5)) {
				Mx3DPointFloat otherPosition;
				Mx3DPointFloat distance;

				otherPosition = r->GetLocal2World()[3];
				distance = m_roi->GetLocal2World()[3];

				distance -= otherPosition;

				float radius = r->GetWorldBoundingSphere().Radius();
				if (distance.LenSquared() <= radius * radius) {
					MxS32 index = -1;
					if (sscanf(r->GetName(), "pammo%d", &index) != 1) {
						assert(0);
					}

					assert(m_world);

#ifdef BETA10
					m_world->EatPizza(index);
#else
					if (m_world->m_pizzas[index].IsValid() && !m_world->m_pizzas[index].IsSharkFood()) {
						m_world->EatPizza(index);
						m_world->m_brickster->FUN_100417c0();
					}
#endif

					if (IsDonut()) {
						assert(SoundManager()->GetCacheSoundManager());
						SoundManager()->GetCacheSoundManager()->Play("dnhitpz", NULL, FALSE);
						m_world->RemoveDonut(*this);
						annihilated = TRUE;
						break;
					}
				}
			}
			else if (!strncmp(r->GetName(), "dammo", 5)) {
				Mx3DPointFloat otherPosition;
				Mx3DPointFloat distance;

				otherPosition = r->GetLocal2World()[3];
				distance = m_roi->GetLocal2World()[3];

				distance -= otherPosition;

				float radius = r->GetWorldBoundingSphere().Radius();
				if (distance.LenSquared() <= radius * radius) {
					MxS32 index = -1;
					if (sscanf(r->GetName(), "dammo%d", &index) != 1) {
						assert(0);
					}

					assert(m_world);

					m_world->EatDonut(index);

					if (IsPizza()) {
						assert(SoundManager()->GetCacheSoundManager());
						SoundManager()->GetCacheSoundManager()->Play("pzhitdn", NULL, FALSE);
						m_world->RemovePizza(*this);
						annihilated = TRUE;
						break;
					}
				}
			}
		}

		if (!annihilated) {
			if (IsPizza()) {
				m_world->FUN_10073360(*this, position);
			}
			else {
				m_world->FUN_10073390(*this, position);
			}

			m_worldSpeed = -1.0f;
		}
	}
}
