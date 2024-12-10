#include "act3ammo.h"

#include "legocachesoundmanager.h"
#include "legocharactermanager.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "roi/legoroi.h"

#include <assert.h>
#include <vec.h>

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

// STUB: LEGO1 0x10053b40
// STUB: BETA10 0x1001db2a
MxResult Act3Ammo::FUN_10053b40(Vector3& p_srcLoc, Vector3& p_srcDir, Vector3& p_srcUp)
{
	// TODO
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
	m_state = 1;
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
	m_state = 1;
	return SUCCESS;
}

// STUB: LEGO1 0x10054050
// STUB: BETA10 0x1001e362
void Act3Ammo::VTable0x70(float p_time)
{
	// TODO
}
