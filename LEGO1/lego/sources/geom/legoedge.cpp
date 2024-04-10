#include "legoedge.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(LegoEdge, 0x24)

// FUNCTION: LEGO1 0x1009a470
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
LegoEdge::~LegoEdge()
{
}

// FUNCTION: LEGO1 0x1009a4d0
LegoEdge* LegoEdge::GetClockwiseEdge(LegoWEEdge* p_face)
{
	if (p_face == m_faceA) {
		return m_cwA;
	}
	else if (p_face == m_faceB) {
		return m_cwB;
	}
	else {
		return NULL;
	}
}

// FUNCTION: LEGO1 0x1009a4f0
LegoEdge* LegoEdge::GetCounterclockwiseEdge(LegoWEEdge* p_face)
{
	if (p_face == m_faceA) {
		return m_ccwA;
	}
	else if (p_face == m_faceB) {
		return m_ccwB;
	}
	else {
		return NULL;
	}
}

// FUNCTION: LEGO1 0x1009a510
Vector3* LegoEdge::GetOpposingPoint(LegoWEEdge* p_face)
{
	return p_face == m_faceA ? m_pointB : m_pointA;
}

// FUNCTION: LEGO1 0x1009a530
Vector3* LegoEdge::GetPoint(LegoWEEdge* p_face)
{
	return p_face == m_faceB ? m_pointB : m_pointA;
}
