#include "legowegedge.h"

#include "legounkown100db7f4.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(LegoWEGEdge, 0x54)
DECOMP_SIZE_ASSERT(LegoWEGEdge::PathWithTrigger, 0x0c)

// FUNCTION: LEGO1 0x1009a730
// FUNCTION: BETA10 0x101830ec
LegoWEGEdge::LegoWEGEdge()
{
	m_unk0x0d = 0;
	m_name = NULL;
	m_unk0x14.Clear();
	m_edgeNormals = NULL;
	m_flags = 0;
	m_numTriggers = 0;
	m_pathTrigger = NULL;
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
	if (m_pathTrigger) {
		delete m_pathTrigger;
	}
	if (m_unk0x50) {
		delete m_unk0x50;
	}
}

// FUNCTION: LEGO1 0x1009a8c0
// FUNCTION: BETA10 0x101832f7
LegoS32 LegoWEGEdge::VTable0x04()
{
	LegoS32 result = 0;
	m_unk0x30.Clear();
	LegoWEEdge::VTable0x04();

	assert(m_numEdges > 1);

	Vector3* local20;
	if (IsEqual(m_edges[0]->m_faceA)) {
		local20 = m_edges[0]->m_pointB;
	}
	else {
		assert(IsEqual(m_edges[0]->m_faceB));
		local20 = m_edges[0]->m_pointA;
	}

	Vector3 *local1c, *local14;
	if (IsEqual(m_edges[1]->m_faceA)) {
		local1c = m_edges[1]->m_pointB;
		local14 = m_edges[1]->m_pointA;
	}
	else {
		assert(IsEqual(m_edges[1]->m_faceB));
		local1c = m_edges[1]->m_pointA;
		local14 = m_edges[1]->m_pointB;
	}

	result = FUN_1009aea0();
	if (result != 0) {
		result = -2;
	}

	assert(m_edgeNormals == NULL);
	m_edgeNormals = new Mx4DPointFloat[m_numEdges];
	assert(m_edgeNormals);

	LegoUnknown100db7f4* edge;
	LegoS32 i;

	for (i = 0; i < m_numEdges; i++) {
		edge = m_edges[i];
		m_unk0x30 += *edge->m_pointA;
		m_unk0x30 += *edge->m_pointB;
	}

	m_unk0x30 /= m_numEdges * 2;
	m_unk0x44 = 0.0f;

	for (i = 0; i < m_numEdges; i++) {
		Mx3DPointFloat local44;
		edge = m_edges[i];

		local44 = *edge->m_pointA;
		local44 -= m_unk0x30;
		float length = local44.LenSquared();

		if (m_unk0x44 < length) {
			m_unk0x44 = length;
		}

		local44 = *edge->m_pointB;
		local44 -= m_unk0x30;
		length = local44.LenSquared();

		if (m_unk0x44 < length) {
			m_unk0x44 = length;
		}
	}

	m_unk0x44 = sqrt((double) m_unk0x44);

	for (i = 0; i < m_numEdges; i++) {
		edge = m_edges[i];
		Vector3& local5c = edge->m_unk0x28;

		if (edge->m_unk0x3c == 0) {
			local5c = *m_edges[i]->m_pointB;
			local5c -= *m_edges[i]->m_pointA;
			edge->m_unk0x3c = local5c.LenSquared();

			if (edge->m_unk0x3c <= 0.0f) {
				assert(0);
				if (result == 0) {
					result = -1;
				}
			}

			edge->m_unk0x3c = sqrt((double) edge->m_unk0x3c);
			local5c /= edge->m_unk0x3c;
		}

		Mx3DPointFloat local58;
		Vector3 local64(&m_edgeNormals[i][0]);
		edge->FUN_1002ddc0(*this, local58);
		local64.EqualsCross(&local58, &m_unk0x14);

		m_edgeNormals[i][3] = -local64.Dot(m_edges[i]->m_pointA, &local64);
		if (m_edgeNormals[i][3] + m_unk0x30.Dot(&m_unk0x30, &local64) < 0.0f) {
			m_edgeNormals[i] *= -1.0f;
		}

		if (edge->GetFaceA() != NULL && edge->GetFaceB() != NULL) {
			edge->SetFlags(LegoUnknown100db7f4::c_bit1 | LegoUnknown100db7f4::c_bit2);
		}
	}

	if (m_numTriggers > 0) {
		Vector3* vTrig1 = m_edges[0]->CCWVertex(*this);
		Vector3* vTrig2 = m_edges[1]->CCWVertex(*this);
		assert(vTrig1 && vTrig2);

		m_unk0x50 = new Mx3DPointFloat();
		*m_unk0x50 = *vTrig2;
		*m_unk0x50 -= *vTrig1;

		if (m_unk0x50->Unitize() < 0) {
			assert(0);
			delete m_unk0x50;
			m_unk0x50 = NULL;
		}

		if (GetNumEdges() == 4) {
			float local98 = 0.0f;
			Mx3DPointFloat localb8(*m_edges[0]->CWVertex(*this));
			Mx3DPointFloat local80(*m_edges[2]->CCWVertex(*this));
			Mx3DPointFloat local94(*vTrig2);

			local94 -= *vTrig1;
			float local9c = sqrt(local94.LenSquared());

			localb8 -= *vTrig1;
			local80 -= *vTrig1;

			float locala4 = localb8.Dot(m_unk0x50, &localb8);
			if (local98 < locala4) {
				local98 = locala4;
			}

			locala4 = local80.Dot(m_unk0x50, &local80);
			if (locala4 < local9c) {
				local9c = locala4;
			}

			if (local9c < local98) {
				result = -3;
			}
			if (local9c - local98 < 0.0025) {
				result = -4;
			}

			local98 += 0.001;
			local9c -= 0.001;

			for (LegoS32 j = 0; j < m_numTriggers; j++) {
				if (m_pathTrigger[j].m_unk0x08 < local98) {
					m_pathTrigger[j].m_unk0x08 = local98;
				}

				if (m_pathTrigger[j].m_unk0x08 > local9c) {
					m_pathTrigger[j].m_unk0x08 = local9c;
				}
			}
		}
		else {
			result = -5;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1009aea0
// FUNCTION: BETA10 0x10183e2a
LegoS32 LegoWEGEdge::FUN_1009aea0()
{
	LegoU32 localc = FALSE;
	Mx3DPointFloat local24;

	if (m_numEdges < 3) {
		return -1;
	}

	Vector3** local8 = new Vector3*[m_numEdges];
	LegoS32 i;

	for (i = 0; i < m_numEdges; i++) {
		local8[i] = m_edges[i]->CWVertex(*this);
	}

	for (i = 2; i < m_numEdges; i++) {
		Mx3DPointFloat local3c;
		Mx3DPointFloat local50;
		float local28 = 0.0f;

		local3c = *local8[i];
		local3c -= *local8[i - 1];
		local50 = *local8[i - 2];
		local50 -= *local8[i - 1];

		local24.EqualsCross(&local50, &local3c);
		local28 = local24.LenSquared();

		if (local28 < 0.00001f) {
			continue;
		}

		float local58 = sqrt((double) local28);
		local24 /= local58;

		if (localc) {
			float local54 = local24.Dot(&m_unk0x14, &local24);
			if (local54 < 0.98) {
				delete[] local8;
				return -2;
			}
		}
		else {
			m_unk0x14[0] = local24[0];
			m_unk0x14[1] = local24[1];
			m_unk0x14[2] = local24[2];
			m_unk0x14[3] = -local8[i]->Dot(local8[i], &local24);
			localc = TRUE;
		}
	}

	if (local8 != NULL) {
		delete[] local8;
	}

	if (!localc) {
		return -1;
	}

	return 0;
}
