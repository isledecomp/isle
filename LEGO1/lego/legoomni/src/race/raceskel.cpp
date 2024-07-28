#include "raceskel.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(RaceSkel, 0x178)

// STUB: LEGO1 0x100719b0
RaceSkel::RaceSkel()
{
	// TODO
}

// FUNCTION: LEGO1 0x10071cb0
// FUNCTION: BETA10 0x100f158b
void RaceSkel::GetCurrentAnimData(float* p_outCurAnimPosition, float* p_outCurAnimDuration)
{
	*p_outCurAnimPosition = m_animPosition;

	assert(m_curAnim >= 0);
	*p_outCurAnimDuration = m_animMaps[m_curAnim]->GetDuration();
}
