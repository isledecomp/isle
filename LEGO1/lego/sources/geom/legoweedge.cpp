#include "legoweedge.h"

#include "assert.h"
#include "decomp.h"
#include "legoedge.h"
#include "legowegedge.h"

DECOMP_SIZE_ASSERT(LegoEdge, 0x24)
DECOMP_SIZE_ASSERT(LegoWEEdge, 0x0c)

// FUNCTION: LEGO1 0x1009a470
// FUNCTION: BETA10 0x10182250
LegoEdge::LegoEdge()
{
	m_faceA = NULL;
	m_faceB = NULL;
	m_ccwA = NULL;
	m_cwA = NULL;
	m_ccwB = NULL;
	m_cwB = NULL;
	m_pointA = NULL;
	m_pointB = NULL;
}

// FUNCTION: LEGO1 0x1009a4c0
// FUNCTION: BETA10 0x101822c2
LegoEdge::~LegoEdge()
{
}

// FUNCTION: BETA10 0x101822e1
LegoResult LegoEdge::SetCounterclockwiseEdge(LegoWEEdge& p_face, LegoEdge* p_edge)
{
	// unreferenced in BETA10, not in LEGO1
	if (&p_face == m_faceA) {
		m_ccwA = p_edge;
		return SUCCESS;
	}
	if (&p_face == m_faceB) {
		m_ccwB = p_edge;
		return SUCCESS;
	}
	return FAILURE;
}

// FUNCTION: BETA10 0x1018233c
LegoResult LegoEdge::SetClockwiseEdge(LegoWEEdge& p_face, LegoEdge* p_edge)
{
	// unreferenced in BETA10, not in LEGO1
	if (&p_face == m_faceA) {
		m_cwA = p_edge;
		return SUCCESS;
	}
	if (&p_face == m_faceB) {
		m_cwB = p_edge;
		return SUCCESS;
	}
	return FAILURE;
}

// FUNCTION: LEGO1 0x1009a4d0
// FUNCTION: BETA10 0x10182397
LegoEdge* LegoEdge::GetClockwiseEdge(LegoWEEdge& p_face)
{
	if (&p_face == m_faceA) {
		return m_cwA;
	}
	if (&p_face == m_faceB) {
		return m_cwB;
	}
	return NULL;
}

// FUNCTION: LEGO1 0x1009a4f0
// FUNCTION: BETA10 0x101823e5
LegoEdge* LegoEdge::GetCounterclockwiseEdge(LegoWEEdge& p_face)
{
	if (&p_face == m_faceA) {
		return m_ccwA;
	}
	if (&p_face == m_faceB) {
		return m_ccwB;
	}
	return NULL;
}

// FUNCTION: LEGO1 0x1009a510
// FUNCTION: BETA10 0x10182433
Vector3* LegoEdge::CWVertex(LegoWEEdge& p_face)
{
	if (m_faceA == &p_face) {
		return m_pointB;
	}
	assert(m_faceB == &p_face);
	return m_pointA;
}

// FUNCTION: LEGO1 0x1009a530
// FUNCTION: BETA10 0x10182498
Vector3* LegoEdge::CCWVertex(LegoWEEdge& p_face)
{
	if (m_faceB == &p_face) {
		return m_pointB;
	}
	assert(m_faceA == &p_face);
	return m_pointA;
}

// FUNCTION: LEGO1 0x1009a550
// FUNCTION: BETA10 0x101824fd
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
