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
Mx3DPointFloat Act3Ammo::g_unk0x10104f08 = Mx3DPointFloat(0.0, 5.0, 0.0);

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
	assert(m_ammoFlag);
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
MxResult Act3Ammo::FUN_10053b40(Vector3& p_srcLoc, Vector3& p_srcDir, Vector3& p_srcUp)
{
	assert(p_srcDir[1] != 0);

	MxFloat local1c = -(p_srcLoc[1] / p_srcDir[1]);
	Mx3DPointFloat local18(p_srcDir);
	Mx3DPointFloat local34;

	local18 *= local1c;
	local18 += p_srcLoc;

	local34[0] = local34[2] = 0.0f;
	local34[1] = -1.0f;

	m_eq[1] = p_srcUp;
	m_eq[2] = p_srcLoc;

	Mx3DPointFloat local48(local34);
	local48 -= m_eq[1];

	for (MxS32 i = 0; i < 3; i++) {
		if (local18[0] == p_srcLoc[0]) {
			return FAILURE;
		}

		m_eq[0][i] = (local48[i] * local48[i] + local48[i] * m_eq[1][i] * 2.0f) / ((local18[i] - p_srcLoc[i]) * 4.0f);
	}

	assert(m_eq[0][0] > 0.000001 || m_eq[0][0] < -0.000001);

	m_unk0x19c = local48[0] / (m_eq[0][0] * 2.0f);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10053cb0
// FUNCTION: BETA10 0x1001ddf4
MxResult Act3Ammo::FUN_10053cb0(LegoPathController* p_p, LegoPathBoundary* p_boundary, MxFloat p_unk0x19c)
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
	m_unk0x19c = p_unk0x19c;
	m_unk0x7c = 0.0f;
	m_lastTime = -1.0f;
	m_actorState = c_one;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10053d30
// FUNCTION: BETA10 0x1001df73
MxResult Act3Ammo::FUN_10053d30(LegoPathController* p_p, MxFloat p_unk0x19c)
{
	assert(p_p);
	assert(IsValid());

	SetBit4(TRUE);

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
	m_unk0x19c = p_unk0x19c;
	m_unk0x7c = 0.0f;
	m_lastTime = -1.0f;
	m_actorState = c_one;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10053db0
// FUNCTION: BETA10 0x1001e0f0
MxResult Act3Ammo::FUN_10053db0(float p_param1, const Matrix4& p_param2)
{
	float local34 = p_param1 * p_param1;

	Vector3 local14(p_param2[0]);
	Vector3 local3c(p_param2[1]);
	Vector3 localc(p_param2[2]);
	Vector3 local30(p_param2[3]);
	Mx3DPointFloat local28;

	local28 = m_eq[1];
	local28 *= p_param1;
	local30 = m_eq[0];
	local30 *= local34;
	local30 += local28;
	local30 += m_eq[2];
	localc = m_eq[0];
	localc *= 2.0f;
	localc *= p_param1;
	localc += m_eq[1];
	localc *= -1.0f;

	if (localc.Unitize() != 0) {
		assert(0);
		return FAILURE;
	}

	local14[1] = local14[2] = 0.0f;
	local14[0] = 1.0f;
	local3c.EqualsCross(&localc, &local14);

	if (local3c.Unitize() != 0) {
		local14[0] = local14[1] = 0.0f;
		local14[2] = 1.0f;
		local3c.EqualsCross(&localc, &local14);

		if (local3c.Unitize() != 0) {
			assert(0);
			return FAILURE;
		}
	}

	local14.EqualsCross(&local3c, &localc);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10054050
// FUNCTION: BETA10 0x1001e362
void Act3Ammo::Animate(float p_time)
{
	assert(IsValid());

	switch (m_actorState & c_maxState) {
	case c_initial:
	case c_one:
		break;
	case c_two:
		m_unk0x158 = p_time + 2000.0f;
		m_actorState = c_three;
		return;
	case c_three:
		MxMatrix transform;
		Vector3 positionRef(transform[3]);

		transform = m_roi->GetLocal2World();

		if (m_unk0x158 > p_time) {
			Mx3DPointFloat position;

			position = positionRef;
			positionRef.Clear();
			transform.RotateX(0.6);
			positionRef = position;
			m_roi->FUN_100a58f0(transform);
			m_roi->VTable0x14();
			return;
		}
		else {
			m_actorState = c_initial;
			m_unk0x158 = 0;

			positionRef -= g_unk0x10104f08;
			m_roi->FUN_100a58f0(transform);
			m_roi->VTable0x14();
			return;
		}
	}

	if (m_worldSpeed <= 0.0f) {
		return;
	}

	if (m_lastTime < 0.0f) {
		m_lastTime = p_time;
		m_unk0x7c = 0.0f;
	}

	MxMatrix local104;
	MxMatrix local60;

	float f = (m_BADuration - m_unk0x7c) / m_worldSpeed + m_lastTime;

	undefined4 localb4 = 0;
	undefined4 localbc = 0;
	MxU32 local14 = FALSE;
	MxU32 localb8 = FALSE;

	if (f >= p_time) {
		m_actorTime = (p_time - m_lastTime) * m_worldSpeed + m_actorTime;
		m_unk0x7c = (p_time - m_lastTime) * m_worldSpeed + m_unk0x7c;
		m_lastTime = p_time;
	}
	else {
		localb8 = TRUE;
		m_unk0x7c = m_BADuration;
		m_lastTime = p_time;
	}

	local104.SetIdentity();

	MxResult r = FUN_10053db0((m_unk0x7c / m_BADuration) * m_unk0x19c, local104);
	assert(r == 0); // SUCCESS

	local60.SetIdentity();

	if (IsPizza()) {
		local60.Scale(2.0f, 2.0f, 2.0f);
	}
	else {
		local60.Scale(5.0f, 5.0f, 5.0f);
	}

	if (localb8) {
		if (m_boundary != NULL) {
			Vector3 local17c(local104[0]);
			Vector3 local184(local104[1]);
			Vector3 local174(local104[2]);

			if (IsPizza()) {
				local184 = *m_boundary->GetUnknown0x14();
				local17c[0] = 1.0f;
				local17c[1] = local17c[2] = 0.0f;
				local174.EqualsCross(&local17c, &local184);
				local174.Unitize();
				local17c.EqualsCross(&local184, &local174);
			}
			else {
				local17c = *m_boundary->GetUnknown0x14();
				local184[0] = 1.0f;
				local184[1] = local184[2] = 0.0f;
				local174.EqualsCross(&local17c, &local184);
				local174.Unitize();
				local184.EqualsCross(&local174, &local17c);
			}
		}

		m_actorState = c_initial;
	}
	else {
		local60.RotateX(m_actorTime / 10.0f);
		local60.RotateY(m_actorTime / 6.0f);
	}

	MxMatrix localb0(local104);
	local104.Product(local60, localb0);
	m_roi->FUN_100a58f0(local104);
	m_roi->VTable0x14();

	if (m_BADuration <= m_unk0x7c) {
		m_worldSpeed = 0.0f;
	}

	Vector3 local68(local104[3]);

	if (localb8) {
		if (IsBit4()) {
			if (IsPizza()) {
				m_world->RemovePizza(*this);
				m_world->FUN_10072ad0(2);
			}
			else {
				m_world->RemoveDonut(*this);
				m_world->FUN_10072ad0(4);
			}
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

			LegoPathActorSet& plpas = m_boundary->GetActors();
			LegoPathActorSet lpas(plpas);

			for (LegoPathActorSet::iterator itpa = lpas.begin(); itpa != lpas.end(); itpa++) {
				if (plpas.find(*itpa) != plpas.end() && this != *itpa) {
					LegoROI* r = (*itpa)->GetROI();
					assert(r);

					if (!strncmp(r->GetName(), "pammo", 5)) {
						Mx3DPointFloat local1c8;
						Mx3DPointFloat local1b4;

						local1c8 = r->GetLocal2World()[3];
						local1b4 = m_roi->GetLocal2World()[3];

						local1b4 -= local1c8;

						float radius = r->GetWorldBoundingSphere().Radius();
						if (local1b4.LenSquared() <= radius * radius) {
							MxS32 index = -1;
							if (sscanf(r->GetName(), "pammo%d", &index) != 1) {
								assert(0);
							}

							assert(m_world);

							if (m_world->m_pizzas[index].IsValid() && !m_world->m_pizzas[index].IsBit5()) {
								m_world->EatPizza(index);
								m_world->m_brickster->FUN_100417c0();
							}

							if (IsDonut()) {
								assert(SoundManager()->GetCacheSoundManager());
								SoundManager()->GetCacheSoundManager()->Play("dnhitpz", NULL, FALSE);
								m_world->RemoveDonut(*this);
								local14 = TRUE;
								break;
							}
						}
					}
					else if (!strncmp(r->GetName(), "dammo", 5)) {
						Mx3DPointFloat local1f8;
						Mx3DPointFloat local1e4;

						local1f8 = r->GetLocal2World()[3];
						local1e4 = m_roi->GetLocal2World()[3];

						local1e4 -= local1f8;

						float radius = r->GetWorldBoundingSphere().Radius();
						if (local1e4.LenSquared() <= radius * radius) {
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
								local14 = TRUE;
								break;
							}
						}
					}
				}
			}

			if (!local14) {
				if (IsPizza()) {
					m_world->FUN_10073360(*this, local68);
				}
				else {
					m_world->FUN_10073390(*this, local68);
				}

				m_worldSpeed = -1.0f;
			}
		}
	}
}
