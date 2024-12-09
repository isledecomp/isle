#include "act3ammo.h"

#include "legocharactermanager.h"
#include "misc.h"
#include "roi/legoroi.h"

#include <assert.h>

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

// STUB: LEGO1 0x10053980
// STUB: BETA10 0x1001d8b3
MxResult Act3Ammo::FUN_10053980(Act3* p_a3, MxU32 p_isDonut, MxS32 p_index)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10053b40
// STUB: BETA10 0x1001db2a
MxResult Act3Ammo::FUN_10053b40(Vector3& p_srcLoc, Vector3& p_srcDir, Vector3& p_srcUp)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10053cb0
// STUB: BETA10 0x1001ddf4
MxResult Act3Ammo::FUN_10053cb0(LegoPathController* p_controller, LegoPathBoundary* p_boundary, MxFloat p_unk0x19c)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10053d30
// STUB: BETA10 0x1001df73
MxResult Act3Ammo::FUN_10053d30(LegoPathController* p_controller, MxFloat p_unk0x19c)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10054050
// STUB: BETA10 0x1001e362
void Act3Ammo::VTable0x70(float p_time)
{
	// TODO
}
