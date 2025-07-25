#include "legoweedge.h"

#include "legoorientededge.h"

DECOMP_SIZE_ASSERT(LegoWEEdge, 0x0c)

// FUNCTION: LEGO1 0x1009a550
LegoWEEdge::LegoWEEdge()
{
	m_edges = NULL;
	m_numEdges = 0;
}

// FUNCTION: LEGO1 0x1009a590
// FUNCTION: BETA10 0x10182530
LegoWEEdge::~LegoWEEdge()
{
	if (m_edges) {
		delete m_edges;
	}
}

// FUNCTION: LEGO1 0x1009a5b0
// FUNCTION: BETA10 0x10182577
LegoS32 LegoWEEdge::LinkEdgesAndFaces()
{
	assert(m_edges);
	assert(m_numEdges);

	for (LegoS32 i = 0; i < m_numEdges; i++) {
		LegoOrientedEdge* e1 = m_edges[i];
		LegoOrientedEdge* e2 = (m_numEdges - 1) == i ? m_edges[0] : m_edges[i + 1];

		if (e2->m_pointA == e1->m_pointA) {
			assert(e1->m_faceA == NULL || e1->m_faceA == this);
			assert(e2->m_faceB == NULL || e2->m_faceB == this);
			assert(e1->m_ccwA == NULL || e1->m_ccwA == e2);
			assert(e2->m_cwB == NULL || e2->m_cwB == e1);
			e1->m_faceA = this;
			e2->m_faceB = this;
			e1->m_ccwA = e2;
			e2->m_cwB = e1;
		}
		else if (e2->m_pointB == e1->m_pointA) {
			assert(e1->m_faceA == NULL || e1->m_faceA == this);
			assert(e2->m_faceA == NULL || e2->m_faceA == this);
			assert(e1->m_ccwA == NULL || e1->m_ccwA == e2);
			assert(e2->m_cwA == NULL || e2->m_cwA == e1);
			e1->m_faceA = this;
			e2->m_faceA = this;
			e1->m_ccwA = e2;
			e2->m_cwA = e1;
		}
		else if (e1->m_pointB == e2->m_pointA) {
			assert(e1->m_faceB == NULL || e1->m_faceB == this);
			assert(e2->m_faceB == NULL || e2->m_faceB == this);
			assert(e1->m_ccwB == NULL || e1->m_ccwB == e2);
			assert(e2->m_cwB == NULL || e2->m_cwB == e1);
			e1->m_faceB = this;
			e2->m_faceB = this;
			e1->m_ccwB = e2;
			e2->m_cwB = e1;
		}
		else {
			assert(e1->m_pointB == e2->m_pointB);
			assert(e1->m_faceB == NULL || e1->m_faceB == this);
			assert(e2->m_faceA == NULL || e2->m_faceA == this);
			assert(e1->m_ccwB == NULL || e1->m_ccwB == e2);
			assert(e2->m_cwA == NULL || e2->m_cwA == e1);
			e1->m_faceB = this;
			e2->m_faceA = this;
			e1->m_ccwB = e2;
			e2->m_cwA = e1;
		}
	}

	return 0;
}
