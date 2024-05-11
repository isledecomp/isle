#include "legopathcontroller.h"

#include "legopathstruct.h"
#include "misc/legostorage.h"
#include "mxmisc.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(LegoPathController, 0x40)
DECOMP_SIZE_ASSERT(LegoPathCtrlEdge, 0x40)

// FUNCTION: LEGO1 0x10044f40
// FUNCTION: BETA10 0x100b6860
LegoPathController::LegoPathController()
{
	m_unk0x08 = NULL;
	m_unk0x0c = NULL;
	m_unk0x10 = NULL;
	m_unk0x14 = NULL;
	m_numL = 0;
	m_numE = 0;
	m_numN = 0;
	m_numT = 0;
}

// STUB: LEGO1 0x10045880
void LegoPathController::Create(MxU8* p_data, Vector3& p_location, MxAtomId& p_trigger)
{
	// TODO

	LegoMemory storage(p_data);
	Read(&storage);
}

// STUB: LEGO1 0x10045b20
void LegoPathController::Destroy()
{
	// TODO
}

// STUB: LEGO1 0x10045c10
MxResult LegoPathController::Tickle()
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10045c20
// FUNCTION: BETA10 0x100b6d80
MxResult LegoPathController::FUN_10045c20(
	LegoPathActor* p_actor,
	const char* p_name,
	MxS32 p_src,
	float p_srcScale,
	MxS32 p_dest,
	float p_destScale
)
{
	if (p_actor->GetController() != NULL) {
		p_actor->GetController()->FUN_10046770(p_actor);
		p_actor->SetController(NULL);
	}

	LegoPathBoundary* pBoundary = GetPathBoundary(p_name);
	LegoEdge* pSrcE = pBoundary->GetEdges()[p_src];
	LegoEdge* pDestE = pBoundary->GetEdges()[p_dest];
	float time = Timer()->GetTime();

	if (p_actor->VTable0x88(pBoundary, time, *pSrcE, p_srcScale, (LegoUnknown100db7f4&) *pDestE, p_destScale) !=
		SUCCESS) {
		return FAILURE;
	}

	p_actor->SetController(this);
	m_actors.insert(p_actor);
	return SUCCESS;
}

// STUB: LEGO1 0x10046770
// FUNCTION: BETA10 0x100b7264
undefined4 LegoPathController::FUN_10046770(LegoPathActor* p_actor)
{
	return 0;
}

// STUB: LEGO1 0x100468f0
// FUNCTION: BETA10 0x100b72f7
void LegoPathController::FUN_100468f0(LegoAnimPresenter* p_presenter)
{
}

// STUB: LEGO1 0x10046930
// FUNCTION: BETA10 0x100b737b
void LegoPathController::FUN_10046930(LegoAnimPresenter* p_presenter)
{
}

// STUB: LEGO1 0x10046b30
MxResult LegoPathController::FUN_10046b30(LegoPathBoundary** p_path, MxS32& p_value)
{
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10046b50
// FUNCTION: BETA10 0x100b7531
LegoPathBoundary* LegoPathController::GetPathBoundary(const char* p_name)
{
	for (MxS32 i = 0; i < m_numL; i++) {
		if (!strcmpi(m_unk0x08[i].GetName(), p_name)) {
			return &m_unk0x08[i];
		}
	}

	return NULL;
}

// STUB: LEGO1 0x10046bb0
void LegoPathController::FUN_10046bb0(LegoWorld* p_world)
{
	// TODO
}

// STUB: LEGO1 0x10046be0
void LegoPathController::Enable(MxBool p_enable)
{
	// TODO
}

// FUNCTION: LEGO1 0x10046e50
// FUNCTION: BETA10 0x100b781f
MxResult LegoPathController::Read(LegoStorage* p_storage)
{
	if (p_storage->Read(&m_numT, sizeof(m_numT)) != SUCCESS) {
		return FAILURE;
	}
	if (m_numT > 0) {
		m_unk0x14 = new LegoPathStruct[m_numT];
	}

	if (p_storage->Read(&m_numN, sizeof(m_numN)) != SUCCESS) {
		return FAILURE;
	}
	if (m_numN > 0) {
		m_unk0x10 = new Mx3DPointFloat[m_numN];
	}

	if (p_storage->Read(&m_numE, sizeof(m_numE)) != SUCCESS) {
		return FAILURE;
	}
	if (m_numE > 0) {
		m_unk0x0c = new LegoPathCtrlEdge[m_numE];
	}

	if (p_storage->Read(&m_numL, sizeof(m_numL)) != SUCCESS) {
		return FAILURE;
	}
	if (m_numL > 0) {
		m_unk0x08 = new LegoPathBoundary[m_numL];
	}

	if (m_numT > 0 && ReadStructs(p_storage) != SUCCESS) {
		return FAILURE;
	}

	if (m_numN > 0) {
		for (MxS32 i = 0; i < m_numN; i++) {
			if (ReadVector(p_storage, m_unk0x10[i]) != SUCCESS) {
				return FAILURE;
			}
		}
	}

	if (m_numE > 0 && ReadEdges(p_storage) != SUCCESS) {
		return FAILURE;
	}

	if (m_numL > 0 && ReadBoundaries(p_storage) != SUCCESS) {
		return FAILURE;
	}

	for (MxS32 j = 0; j < m_numE; j++) {
		m_pfsE.insert(&m_unk0x0c[j]);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10047b30
// FUNCTION: BETA10 0x100b7cd6
MxResult LegoPathController::ReadStructs(LegoStorage* p_storage)
{
	for (MxS32 i = 0; i < m_numT; i++) {
		MxU8 length = 0;

		if (p_storage->Read(&length, sizeof(length)) != SUCCESS) {
			return FAILURE;
		}

		if (length > 0) {
			m_unk0x14[i].m_name = new char[length + 1];

			if (p_storage->Read(m_unk0x14[i].m_name, length) != SUCCESS) {
				return FAILURE;
			}

			m_unk0x14[i].m_name[length] = '\0';
		}

		if (p_storage->Read(&m_unk0x14[i].m_unk0x08, sizeof(m_unk0x14[i].m_unk0x08)) != SUCCESS) {
			return FAILURE;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10047c10
// FUNCTION: BETA10 0x100b7df3
MxResult LegoPathController::ReadEdges(LegoStorage* p_storage)
{
	for (MxS32 i = 0; i < m_numE; i++) {
		LegoPathCtrlEdge& edge = m_unk0x0c[i];
		MxU16 s;

		if (p_storage->Read(&edge.m_flags, sizeof(edge.m_flags)) != SUCCESS) {
			return FAILURE;
		}

		if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
			return FAILURE;
		}
		edge.m_pointA = &m_unk0x10[s];

		if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
			return FAILURE;
		}
		edge.m_pointB = &m_unk0x10[s];

		if (edge.m_flags & LegoUnknown100db7f4::c_bit3) {
			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}
			edge.m_faceA = &m_unk0x08[s];

			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}
			edge.m_ccwA = &m_unk0x0c[s];

			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}
			edge.m_cwA = &m_unk0x0c[s];
		}

		if (edge.m_flags & LegoUnknown100db7f4::c_bit4) {
			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}
			edge.m_faceB = &m_unk0x08[s];

			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}
			edge.m_ccwB = &m_unk0x0c[s];

			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}
			edge.m_cwB = &m_unk0x0c[s];
		}

		if (ReadVector(p_storage, edge.m_unk0x28) != SUCCESS) {
			return FAILURE;
		}

		if (p_storage->Read(&edge.m_unk0x3c, sizeof(edge.m_unk0x3c)) != SUCCESS) {
			return FAILURE;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10047e90
// FUNCTION: BETA10 0x100b8293
MxResult LegoPathController::ReadBoundaries(LegoStorage* p_storage)
{
	for (MxS32 i = 0; i < m_numL; i++) {
		LegoPathBoundary& boundary = m_unk0x08[i];
		MxU8 numE;
		MxU16 s;
		MxU8 j;

		if (p_storage->Read(&numE, sizeof(numE)) != SUCCESS) {
			return FAILURE;
		}

		boundary.m_edgeNormals = new Mx4DPointFloat[numE];

		LegoEdge** edges = new LegoEdge*[numE];
		boundary.SetEdges(edges, numE);

		for (j = 0; j < numE; j++) {
			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}

			edges[j] = &m_unk0x0c[s];
		}

		if (p_storage->Read(&boundary.m_unk0x0c, sizeof(boundary.m_unk0x0c)) != SUCCESS) {
			return FAILURE;
		}

		if (p_storage->Read(&boundary.m_unk0x0d, sizeof(boundary.m_unk0x0d)) != SUCCESS) {
			return FAILURE;
		}

		MxU8 length;
		if (p_storage->Read(&length, sizeof(length)) != SUCCESS) {
			return FAILURE;
		}

		if (length > 0) {
			boundary.m_name = new char[length + 1];

			if (p_storage->Read(boundary.m_name, length) != SUCCESS) {
				return FAILURE;
			}

			boundary.m_name[length] = '\0';
		}

		if (ReadVector(p_storage, boundary.m_unk0x14) != SUCCESS) {
			return FAILURE;
		}

		for (j = 0; j < numE; j++) {
			if (ReadVector(p_storage, boundary.m_edgeNormals[j]) != SUCCESS) {
				return FAILURE;
			}
		}

		if (ReadVector(p_storage, boundary.m_unk0x30) != SUCCESS) {
			return FAILURE;
		}

		if (p_storage->Read(&boundary.m_unk0x44, sizeof(boundary.m_unk0x44)) != SUCCESS) {
			return FAILURE;
		}

		if (p_storage->Read(&boundary.m_unk0x48, sizeof(boundary.m_unk0x48)) != SUCCESS) {
			return FAILURE;
		}

		if (boundary.m_unk0x48 > 0) {
			boundary.m_unk0x50 = new Mx3DPointFloat;
			boundary.m_unk0x4c = new LegoWEGEdge::Path[boundary.m_unk0x48];

			for (j = 0; j < boundary.m_unk0x48; j++) {
				if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
					return FAILURE;
				}

				boundary.m_unk0x4c[j].m_unk0x00 = &m_unk0x14[s];

				if (p_storage->Read(&boundary.m_unk0x4c[j].m_unk0x04, sizeof(boundary.m_unk0x4c[j].m_unk0x04)) !=
					SUCCESS) {
					return FAILURE;
				}

				if (p_storage->Read(&boundary.m_unk0x4c[j].m_unk0x08, sizeof(boundary.m_unk0x4c[j].m_unk0x08)) !=
					SUCCESS) {
					return FAILURE;
				}
			}

			if (ReadVector(p_storage, *boundary.m_unk0x50) != SUCCESS) {
				return FAILURE;
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100482b0
// FUNCTION: BETA10 0x100b8864
MxResult LegoPathController::ReadVector(LegoStorage* p_storage, Mx3DPointFloat& p_vec)
{
	if (p_storage->Read(p_vec.GetData(), sizeof(float) * 3) != SUCCESS) {
		return FAILURE;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100482e0
// FUNCTION: BETA10 0x100b88a1
MxResult LegoPathController::ReadVector(LegoStorage* p_storage, Mx4DPointFloat& p_vec)
{
	if (p_storage->Read(p_vec.GetData(), sizeof(float) * 4) != SUCCESS) {
		return FAILURE;
	}

	return SUCCESS;
}
