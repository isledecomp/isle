#include "act3ammo.h"

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

// FUNCTION: LEGO1 0x100537f0
// FUNCTION: BETA10 0x1001d648
Act3Ammo::Act3Ammo()
{
	m_ammoFlag = 0;
	m_a3 = NULL;
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
MxResult Act3Ammo::Create(Act3* p_a3, MxU32 p_isPizza, MxS32 p_index)
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

	m_a3 = p_a3;
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

// STUB: LEGO1 0x10054050
// STUB: BETA10 0x1001e362
void Act3Ammo::UpdateState(float p_time)
{
	// TODO
}
