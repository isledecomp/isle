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
	m_unk0x154 = 0;
	m_unk0x15c = 0;
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

// STUB: LEGO1 0x10054050
// STUB: BETA10 0x1001e362
void Act3Ammo::VTable0x70(float p_time)
{
	// TODO
}
