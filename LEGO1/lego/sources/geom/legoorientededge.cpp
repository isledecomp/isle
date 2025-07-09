#include "legoorientededge.h"

DECOMP_SIZE_ASSERT(LegoOrientedEdge, 0x40)

// FUNCTION: LEGO1 0x1009a630
// FUNCTION: BETA10 0x10183050
LegoOrientedEdge::LegoOrientedEdge()
{
	m_flags = 0;
	m_dir.Clear();
	m_length = 0.0f;
}
