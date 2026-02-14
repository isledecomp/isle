#include "legoedge.h"

#include "assert.h"
#include "decomp.h"

DECOMP_SIZE_ASSERT(LegoEdge, 0x24)

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
