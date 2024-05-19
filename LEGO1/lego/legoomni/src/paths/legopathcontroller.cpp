#include "legopathcontroller.h"

#include "legopathstruct.h"
#include "misc/legostorage.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(LegoPathController, 0x40)
DECOMP_SIZE_ASSERT(LegoPathCtrlEdge, 0x40)
DECOMP_SIZE_ASSERT(LegoPathController::CtrlBoundary, 0x08)
DECOMP_SIZE_ASSERT(LegoPathController::CtrlEdge, 0x08)

// GLOBAL: LEGO1 0x100d7cc8
MxU32 g_unk0x100d7cc8[] = {2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 0};

// GLOBAL: LEGO1 0x100d7d08
MxU32 g_unk0x100d7d08[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// GLOBAL: LEGO1 0x100f42e8
LegoPathController::CtrlBoundary* g_ctrlBoundariesA = NULL;

// GLOBAL: LEGO1 0x100f42ec
LegoPathController::CtrlEdge* g_ctrlEdgesA = NULL;

// GLOBAL: LEGO1 0x100f42f0
const char* g_unk0x100f42f0[] = {
	"edg03_21",
	"edg03_23",
	"edg03_30",
	"edg03_31",
	"edg03_39",
	"edg03_40",
	"edg03_91",
	"edg03_92",
	"edg03_99",
	"edg03_100",
	"edg03_112",
	"edg03_113",
	"edg10_61",
	"edg10_62",
	"edg10_55",
	"edg10_58"
};

// GLOBAL: LEGO1 0x100f4330
const char* g_unk0x100f4330[] = {
	"edg03_06",
	"edg03_21",
	"edg03_30",
	"edg03_148",
	"edg03_39",
	"edg03_91",
	"edg03_99",
	"edg03_112",
	"edg03_800",
	"edg03_135"
};

// GLOBAL: LEGO1 0x100f4358
LegoPathController::CtrlBoundary* g_ctrlBoundariesB = NULL;

// GLOBAL: LEGO1 0x100f435c
LegoPathController::CtrlEdge* g_ctrlEdgesB = NULL;

// FUNCTION: LEGO1 0x10044f40
// FUNCTION: BETA10 0x100b6860
LegoPathController::LegoPathController()
{
	m_boundaries = NULL;
	m_edges = NULL;
	m_unk0x10 = NULL;
	m_structs = NULL;
	m_numL = 0;
	m_numE = 0;
	m_numN = 0;
	m_numT = 0;
}

// FUNCTION: LEGO1 0x10045880
// FUNCTION: BETA10 0x100b6959
MxResult LegoPathController::Create(MxU8* p_data, const Vector3& p_location, const MxAtomId& p_trigger)
{
	MxResult result = FAILURE;
	LegoMemory storage(p_data);

	if ((result = Read(&storage)) == SUCCESS) {
		MxS32 i;

		for (i = 0; i < m_numT; i++) {
			m_structs[i].SetAtomId(p_trigger);
		}

		for (i = 0; i < m_numN; i++) {
			// TODO: Fix call
			((Vector3&) m_unk0x10[i]).Add(&p_location);
		}

		for (i = 0; i < m_numL; i++) {
			LegoPathBoundary& boundary = m_boundaries[i];
			MxS32 j;

			for (j = 0; j < sizeOfArray(g_unk0x100f42f0); j++) {
				if (!strcmpi(g_unk0x100f42f0[j], boundary.GetName())) {
					g_ctrlBoundariesA[j].m_controller = this;
					g_ctrlBoundariesA[j].m_boundary = &boundary;

					MxU32 edge = g_unk0x100d7cc8[j];
					g_ctrlEdgesA[j].m_controller = this;
					g_ctrlEdgesA[j].m_edge = boundary.GetEdges()[edge];
				}
			}

			for (j = 0; j < sizeOfArray(g_unk0x100f4330); j++) {
				if (!strcmpi(g_unk0x100f4330[j], boundary.GetName())) {
					g_ctrlBoundariesB[j].m_controller = this;
					g_ctrlBoundariesB[j].m_boundary = &boundary;
					g_ctrlEdgesB[j].m_controller = this;
					g_ctrlEdgesB[j].m_edge = boundary.GetEdges()[g_unk0x100d7d08[j]];
				}
			}
		}

		TickleManager()->RegisterClient(this, 10);
	}

	if (result != SUCCESS) {
		Destroy();
	}

	return result;
}

// FUNCTION: LEGO1 0x10045b20
// FUNCTION: BETA10 0x100b6b8a
void LegoPathController::Destroy()
{
	TickleManager()->UnregisterClient(this);

	if (m_boundaries != NULL) {
		delete[] m_boundaries;
	}
	m_boundaries = NULL;
	m_numL = 0;

	if (m_unk0x10 != NULL) {
		delete[] m_unk0x10;
	}
	m_unk0x10 = NULL;
	m_numN = 0;

	if (m_structs != NULL) {
		delete[] m_structs;
	}
	m_structs = NULL;
	m_numT = 0;

	if (m_edges != NULL) {
		delete[] m_edges;
	}
	m_edges = NULL;
	m_numE = 0;

	MxS32 j;
	for (j = 0; j < sizeOfArray(g_unk0x100f42f0); j++) {
		if (g_ctrlBoundariesA[j].m_controller == this) {
			g_ctrlBoundariesA[j].m_controller = NULL;
			g_ctrlBoundariesA[j].m_boundary = NULL;
		}

		if (g_ctrlEdgesA[j].m_controller == this) {
			g_ctrlEdgesA[j].m_controller = NULL;
			g_ctrlEdgesA[j].m_edge = NULL;
		}
	}

	for (j = 0; j < sizeOfArray(g_unk0x100f4330); j++) {
		if (g_ctrlBoundariesB[j].m_controller == this) {
			g_ctrlBoundariesB[j].m_controller = NULL;
			g_ctrlBoundariesB[j].m_boundary = NULL;
		}

		if (g_ctrlEdgesB[j].m_controller == this) {
			g_ctrlEdgesB[j].m_controller = NULL;
			g_ctrlEdgesB[j].m_edge = NULL;
		}
	}
}

// FUNCTION: LEGO1 0x10045c10
// FUNCTION: BETA10 0x100b6d60
MxResult LegoPathController::Tickle()
{
	FUN_10046970();
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
		p_actor->GetController()->RemoveActor(p_actor);
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

// FUNCTION: LEGO1 0x10046050
// FUNCTION: BETA10 0x100b6f35
MxResult LegoPathController::FUN_10046050(
	LegoPathActor* p_actor,
	LegoAnimPresenter* p_presenter,
	Vector3& p_position,
	Vector3& p_direction
)
{
	LegoPathBoundary* boundary = NULL;
	float time = Timer()->GetTime();

	if (p_actor->GetController() != NULL) {
		p_actor->GetController()->RemoveActor(p_actor);
		p_actor->SetController(NULL);
	}

	for (MxS32 i = 0; i < m_numL; i++) {
		LegoPathBoundary& b = m_boundaries[i];
		LegoAnimPresenterSet& presenters = b.GetPresenters();
		LegoAnimPresenter* presenter = p_presenter;

		if (presenters.find(presenter) != presenters.end()) {
			MxS32 j;

			for (j = 0; j < b.GetNumEdges(); j++) {
				Mx4DPointFloat normal(*b.GetEdgeNormal(j));

				if (p_position.Dot(&p_position, &normal) + normal[3] < 0.0f) {
					break;
				}
			}

			if (b.GetNumEdges() == j) {
				if (boundary != NULL) {
					return FAILURE;
				}

				boundary = &b;
			}
		}
	}

	if (boundary == NULL) {
		return FAILURE;
	}

	for (MxS32 j = 0; j < boundary->GetNumEdges(); j++) {
		LegoUnknown100db7f4* edge = (LegoUnknown100db7f4*) boundary->GetEdges()[j];

		if (edge->GetMask0x03()) {
			Mx3DPointFloat vec;

			if (((LegoUnknown100db7f4*) edge->GetClockwiseEdge(*boundary))->FUN_1002ddc0(*boundary, vec) == SUCCESS &&
				vec.Dot(&vec, &p_direction) < 0.0f) {
				edge =
					(LegoUnknown100db7f4*) edge->GetCounterclockwiseEdge(*boundary)->GetCounterclockwiseEdge(*boundary);
			}

			if (!edge->GetMask0x03()) {
				return FAILURE;
			}

			if (p_actor->VTable0x84(boundary, time, p_position, p_direction, *edge, 0.5f) == SUCCESS) {
				p_actor->SetController(this);
				m_actors.insert(p_actor);
				return SUCCESS;
			}
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100466a0
// FUNCTION: BETA10 0x100b71fe
MxResult LegoPathController::AddActor(LegoPathActor* p_actor)
{
	if (p_actor->GetController() != NULL) {
		p_actor->GetController()->RemoveActor(p_actor);
		p_actor->SetController(NULL);
	}

	m_actors.insert(p_actor);
	p_actor->SetController(this);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10046770
// FUNCTION: BETA10 0x100b7264
MxResult LegoPathController::RemoveActor(LegoPathActor* p_actor)
{
	MxResult result = FAILURE;

	p_actor->VTable0xc4();
	m_actors.erase(p_actor);

	for (MxS32 i = 0; i < m_numL; i++) {
		if (m_boundaries[i].RemoveActor(p_actor) == SUCCESS) {
			result = SUCCESS;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x100468f0
// FUNCTION: BETA10 0x100b72f7
void LegoPathController::FUN_100468f0(LegoAnimPresenter* p_presenter)
{
	for (MxS32 i = 0; i < m_numL; i++) {
		if (!(m_boundaries[i].m_flags & LegoWEGEdge::c_bit3)) {
			m_boundaries[i].FUN_10057fe0(p_presenter);
		}
	}
}

// FUNCTION: LEGO1 0x10046930
// FUNCTION: BETA10 0x100b737b
void LegoPathController::FUN_10046930(LegoAnimPresenter* p_presenter)
{
	for (MxS32 i = 0; i < m_numL; i++) {
		m_boundaries[i].FUN_100586e0(p_presenter);
	}
}

// FUNCTION: LEGO1 0x10046970
// FUNCTION: BETA10 0x100b73d8
void LegoPathController::FUN_10046970()
{
	float time = Timer()->GetTime();

	LegoPathActorSet lpas(m_actors);

	for (LegoPathActorSet::iterator itpa = lpas.begin(); itpa != lpas.end(); itpa++) {
		LegoPathActor* actor = *itpa;

		if (m_actors.find(actor) != m_actors.end()) {
			if (!((MxU8) actor->GetState() & LegoPathActor::c_bit3)) {
				actor->VTable0x70(time);
			}
		}
	}
}

// FUNCTION: LEGO1 0x10046b30
MxResult LegoPathController::FUN_10046b30(LegoPathBoundary*& p_boundaries, MxS32& p_numL)
{
	p_boundaries = m_boundaries;
	p_numL = m_numL;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10046b50
// FUNCTION: BETA10 0x100b7531
LegoPathBoundary* LegoPathController::GetPathBoundary(const char* p_name)
{
	for (MxS32 i = 0; i < m_numL; i++) {
		if (!strcmpi(m_boundaries[i].GetName(), p_name)) {
			return &m_boundaries[i];
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x10046bb0
// FUNCTION: BETA10 0x100b75bc
void LegoPathController::FUN_10046bb0(LegoWorld* p_world)
{
	for (MxS32 i = 0; i < m_numT; i++) {
		m_structs[i].SetWorld(p_world);
	}
}

// FUNCTION: LEGO1 0x10046be0
// FUNCTION: BETA10 0x100b7614
void LegoPathController::Enable(MxBool p_enable)
{
	if (p_enable) {
		TickleManager()->RegisterClient(this, 10);
	}
	else {
		TickleManager()->UnregisterClient(this);
	}
}

// FUNCTION: LEGO1 0x10046c10
// FUNCTION: BETA10 0x100b767a
MxResult LegoPathController::Init()
{
	if (g_ctrlBoundariesA != NULL || g_ctrlEdgesA != NULL || g_ctrlBoundariesB != NULL || g_ctrlEdgesB != NULL) {
		return FAILURE;
	}

	g_ctrlBoundariesA = new CtrlBoundary[sizeOfArray(g_unk0x100f42f0)];
	g_ctrlEdgesA = new CtrlEdge[sizeOfArray(g_unk0x100f42f0)];
	g_ctrlBoundariesB = new CtrlBoundary[sizeOfArray(g_unk0x100f4330)];
	g_ctrlEdgesB = new CtrlEdge[sizeOfArray(g_unk0x100f4330)];
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10046de0
// FUNCTION: BETA10 0x100b779e
MxResult LegoPathController::Reset()
{
	if (g_ctrlBoundariesA == NULL || g_ctrlEdgesA == NULL) {
		return FAILURE;
	}

	delete[] g_ctrlBoundariesA;
	delete[] g_ctrlEdgesA;
	delete[] g_ctrlBoundariesB;
	delete[] g_ctrlEdgesB;
	g_ctrlBoundariesA = NULL;
	g_ctrlEdgesA = NULL;
	g_ctrlBoundariesB = NULL;
	g_ctrlEdgesB = NULL;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10046e50
// FUNCTION: BETA10 0x100b781f
MxResult LegoPathController::Read(LegoStorage* p_storage)
{
	if (p_storage->Read(&m_numT, sizeof(m_numT)) != SUCCESS) {
		return FAILURE;
	}
	if (m_numT > 0) {
		m_structs = new LegoPathStruct[m_numT];
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
		m_edges = new LegoPathCtrlEdge[m_numE];
	}

	if (p_storage->Read(&m_numL, sizeof(m_numL)) != SUCCESS) {
		return FAILURE;
	}
	if (m_numL > 0) {
		m_boundaries = new LegoPathBoundary[m_numL];
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
		m_pfsE.insert(&m_edges[j]);
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
			m_structs[i].m_name = new char[length + 1];

			if (p_storage->Read(m_structs[i].m_name, length) != SUCCESS) {
				return FAILURE;
			}

			m_structs[i].m_name[length] = '\0';
		}

		if (p_storage->Read(&m_structs[i].m_unk0x08, sizeof(m_structs[i].m_unk0x08)) != SUCCESS) {
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
		LegoPathCtrlEdge& edge = m_edges[i];
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
			edge.m_faceA = &m_boundaries[s];

			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}
			edge.m_ccwA = &m_edges[s];

			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}
			edge.m_cwA = &m_edges[s];
		}

		if (edge.m_flags & LegoUnknown100db7f4::c_bit4) {
			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}
			edge.m_faceB = &m_boundaries[s];

			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}
			edge.m_ccwB = &m_edges[s];

			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}
			edge.m_cwB = &m_edges[s];
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
		LegoPathBoundary& boundary = m_boundaries[i];
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

			edges[j] = &m_edges[s];
		}

		if (p_storage->Read(&boundary.m_flags, sizeof(boundary.m_flags)) != SUCCESS) {
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

				boundary.m_unk0x4c[j].m_unk0x00 = &m_structs[s];

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
