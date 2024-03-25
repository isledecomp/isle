#include "legoweedge.h"

DECOMP_SIZE_ASSERT(Edge, 0x24)
DECOMP_SIZE_ASSERT(EdgePair, 0x08)
DECOMP_SIZE_ASSERT(LegoWEEdge, 0x0c)

// FUNCTION: LEGO1 0x1009a550
LegoWEEdge::LegoWEEdge()
{
	m_edges = NULL;
	m_numEdges = 0;
}
