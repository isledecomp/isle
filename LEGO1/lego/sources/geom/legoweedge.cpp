#include "legoweedge.h"

DECOMP_SIZE_ASSERT(LegoWEEdge, 0x0c)

// FUNCTION: LEGO1 0x1009a550
LegoWEEdge::LegoWEEdge()
{
	m_edges = NULL;
	m_numEdges = 0;
}

// FUNCTION: LEGO1 0x1009a590
LegoWEEdge::~LegoWEEdge()
{
	if (m_edges) {
		delete m_edges;
	}
}

// FUNCTION: LEGO1 0x1009a5b0
LegoResult LegoWEEdge::VTable0x04()
{
	for (LegoS32 i = 0; i < m_numEdges; i++) {
		LegoEdge* e1 = m_edges[i];
		LegoEdge* e2 = (m_numEdges - i) == 1 ? m_edges[0] : m_edges[i + 1];

		if (e2->m_pointA == e1->m_pointA) {
			e1->m_faceA = this;
			e2->m_faceB = this;
			e1->m_ccwA = e2;
			e2->m_cwB = e1;
		}
		else if (e2->m_pointB == e1->m_pointA) {
			e1->m_faceA = this;
			e2->m_faceA = this;
			e1->m_ccwA = e2;
			e2->m_cwA = e1;
		}
		else if (e1->m_pointB == e2->m_pointA) {
			e1->m_faceB = this;
			e2->m_faceB = this;
			e1->m_ccwB = e2;
			e2->m_cwB = e1;
		}
		else {
			e1->m_faceB = this;
			e2->m_faceA = this;
			e1->m_ccwB = e2;
			e2->m_cwA = e1;
		}
	}

	return SUCCESS;
}
