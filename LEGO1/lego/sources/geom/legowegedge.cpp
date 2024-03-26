#include "legowegedge.h"

DECOMP_SIZE_ASSERT(LegoWEGEdge, 0x54)

// FUNCTION: LEGO1 0x1009a730
LegoWEGEdge::LegoWEGEdge()
{
	m_unk0x0d = 0;
	m_name = NULL;
	m_unk0x14.Clear();
	m_edgeNormals = NULL;
	m_unk0x0c = 0;
	m_unk0x48 = 0;
	m_unk0x4c = NULL;
	m_unk0x50 = NULL;
}

// FUNCTION: LEGO1 0x1009a800
LegoWEGEdge::~LegoWEGEdge()
{
	if (m_edges) {
		delete[] m_edges;
		m_edges = NULL;
	}
	if (m_name) {
		delete[] m_name;
	}
	if (m_edgeNormals) {
		delete[] m_edgeNormals;
	}
	if (m_unk0x4c) {
		delete m_unk0x4c;
	}
	if (m_unk0x50) {
		delete m_unk0x50;
	}
}

// STUB: LEGO1 0x1009a8c0
LegoResult LegoWEGEdge::VTable0x04()
{
	// TODO
	return SUCCESS;
}
