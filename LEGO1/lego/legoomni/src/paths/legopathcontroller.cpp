#include "legopathcontroller.h"

#include "legopathedgecontainer.h"
#include "misc/legostorage.h"
#include "mxmisc.h"
#include "mxticklemanager.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(LegoPathController, 0x40)
DECOMP_SIZE_ASSERT(LegoPathCtrlEdge, 0x40)
DECOMP_SIZE_ASSERT(LegoPathController::CtrlBoundary, 0x08)
DECOMP_SIZE_ASSERT(LegoPathController::CtrlEdge, 0x08)

// GLOBAL: LEGO1 0x100d7cc8
MxU32 g_ctrlEdgesNamesA[] = {2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 0};

// GLOBAL: LEGO1 0x100d7d08
MxU32 g_ctrlEdgesNamesB[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// GLOBAL: LEGO1 0x100f42e8
// GLOBAL: BETA10 0x101f25f0
LegoPathController::CtrlBoundary* LegoPathController::g_ctrlBoundariesA = NULL;

// GLOBAL: LEGO1 0x100f42ec
// GLOBAL: BETA10 0x101f25f4
LegoPathController::CtrlEdge* LegoPathController::g_ctrlEdgesA = NULL;

// GLOBAL: LEGO1 0x100f42f0
const char* LegoPathController::g_ctrlBoundariesNamesA[] = {
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
const char* LegoPathController::g_ctrlBoundariesNamesB[] = {
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
LegoPathController::CtrlBoundary* LegoPathController::g_ctrlBoundariesB = NULL;

// GLOBAL: LEGO1 0x100f435c
LegoPathController::CtrlEdge* LegoPathController::g_ctrlEdgesB = NULL;

// FUNCTION: LEGO1 0x10044f40
// FUNCTION: BETA10 0x100b6860
LegoPathController::LegoPathController()
{
	m_boundaries = NULL;
	m_edges = NULL;
	m_nodes = NULL;
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
			m_nodes[i] += p_location;
		}

		for (i = 0; i < m_numL; i++) {
			LegoPathBoundary& boundary = m_boundaries[i];
			MxS32 j;

			for (j = 0; j < sizeOfArray(g_ctrlBoundariesNamesA); j++) {
				if (!strcmpi(g_ctrlBoundariesNamesA[j], boundary.GetName())) {
					g_ctrlBoundariesA[j].m_controller = this;
					g_ctrlBoundariesA[j].m_boundary = &boundary;

					MxU32 edge = g_ctrlEdgesNamesA[j];
					g_ctrlEdgesA[j].m_controller = this;
					g_ctrlEdgesA[j].m_edge = boundary.GetEdges()[edge];
				}
			}

			for (j = 0; j < sizeOfArray(g_ctrlBoundariesNamesB); j++) {
				if (!strcmpi(g_ctrlBoundariesNamesB[j], boundary.GetName())) {
					g_ctrlBoundariesB[j].m_controller = this;
					g_ctrlBoundariesB[j].m_boundary = &boundary;
					g_ctrlEdgesB[j].m_controller = this;
					g_ctrlEdgesB[j].m_edge = boundary.GetEdges()[g_ctrlEdgesNamesB[j]];
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

	if (m_nodes != NULL) {
		delete[] m_nodes;
	}
	m_nodes = NULL;
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
	for (j = 0; j < sizeOfArray(g_ctrlBoundariesNamesA); j++) {
		if (g_ctrlBoundariesA[j].m_controller == this) {
			g_ctrlBoundariesA[j].m_controller = NULL;
			g_ctrlBoundariesA[j].m_boundary = NULL;
		}

		if (g_ctrlEdgesA[j].m_controller == this) {
			g_ctrlEdgesA[j].m_controller = NULL;
			g_ctrlEdgesA[j].m_edge = NULL;
		}
	}

	for (j = 0; j < sizeOfArray(g_ctrlBoundariesNamesB); j++) {
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
	AnimateActors();
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10045c20
// FUNCTION: BETA10 0x100b6d80
MxResult LegoPathController::PlaceActor(
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

	assert(pBoundary);
	assert(p_src < pBoundary->GetNumEdges() && p_dest < pBoundary->GetNumEdges());

	LegoEdge* pSrcE = pBoundary->GetEdges()[p_src];
	LegoEdge* pDestE = pBoundary->GetEdges()[p_dest];

	assert(pSrcE && pDestE);

	float time = Timer()->GetTime();
	MxResult result =
		p_actor->VTable0x88(pBoundary, time, *pSrcE, p_srcScale, (LegoOrientedEdge&) *pDestE, p_destScale);

	if (result != SUCCESS) {
		assert(0);
		return FAILURE;
	}

	p_actor->SetController(this);
	m_actors.insert(p_actor);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10046050
// FUNCTION: BETA10 0x100b6f35
MxResult LegoPathController::PlaceActor(
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

				if (p_position.Dot(p_position, normal) + normal[3] < 0.0f) {
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
		LegoOrientedEdge* edge = (LegoOrientedEdge*) boundary->GetEdges()[j];

		if (edge->GetMask0x03()) {
			Mx3DPointFloat vec;

			if (((LegoOrientedEdge*) edge->GetClockwiseEdge(*boundary))->GetFaceNormal(*boundary, vec) == SUCCESS &&
				vec.Dot(vec, p_direction) < 0.0f) {
				edge = (LegoOrientedEdge*) edge->GetCounterclockwiseEdge(*boundary)->GetCounterclockwiseEdge(*boundary);
			}

			if (!edge->GetMask0x03()) {
				return FAILURE;
			}

			if (p_actor->VTable0x84(boundary, time, p_position, p_direction, edge, 0.5f) == SUCCESS) {
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
MxResult LegoPathController::PlaceActor(LegoPathActor* p_actor)
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
void LegoPathController::AddPresenterIfInRange(LegoAnimPresenter* p_presenter)
{
	for (MxS32 i = 0; i < m_numL; i++) {
		if (!(m_boundaries[i].m_flags & LegoWEGEdge::c_bit3)) {
			m_boundaries[i].AddPresenterIfInRange(p_presenter);
		}
	}
}

// FUNCTION: LEGO1 0x10046930
// FUNCTION: BETA10 0x100b737b
void LegoPathController::RemovePresenterFromBoundaries(LegoAnimPresenter* p_presenter)
{
	for (MxS32 i = 0; i < m_numL; i++) {
		m_boundaries[i].RemovePresenter(p_presenter);
	}
}

// FUNCTION: LEGO1 0x10046970
// FUNCTION: BETA10 0x100b73d8
void LegoPathController::AnimateActors()
{
	float time = Timer()->GetTime();

	LegoPathActorSet lpas(m_actors);

	for (LegoPathActorSet::iterator itpa = lpas.begin(); itpa != lpas.end(); itpa++) {
		LegoPathActor* actor = *itpa;

		if (m_actors.find(actor) != m_actors.end()) {
			if (!((MxU8) actor->GetActorState() & LegoPathActor::c_disabled)) {
				actor->Animate(time);
			}
		}
	}
}

// FUNCTION: LEGO1 0x10046b30
MxResult LegoPathController::GetBoundaries(LegoPathBoundary*& p_boundaries, MxS32& p_numL)
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
void LegoPathController::SetWorld(LegoWorld* p_world)
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

	g_ctrlBoundariesA = new CtrlBoundary[sizeOfArray(g_ctrlBoundariesNamesA)];
	g_ctrlEdgesA = new CtrlEdge[sizeOfArray(g_ctrlBoundariesNamesA)];
	g_ctrlBoundariesB = new CtrlBoundary[sizeOfArray(g_ctrlBoundariesNamesB)];
	g_ctrlEdgesB = new CtrlEdge[sizeOfArray(g_ctrlBoundariesNamesB)];
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
	if (p_storage->Read(&m_numT, sizeof(MxU16)) != SUCCESS) {
		return FAILURE;
	}
	if (m_numT > 0) {
		m_structs = new LegoPathStruct[m_numT];
	}

	if (p_storage->Read(&m_numN, sizeof(MxU16)) != SUCCESS) {
		return FAILURE;
	}
	if (m_numN > 0) {
		m_nodes = new Mx3DPointFloat[m_numN];
	}

	if (p_storage->Read(&m_numE, sizeof(MxU16)) != SUCCESS) {
		return FAILURE;
	}
	if (m_numE > 0) {
		m_edges = new LegoPathCtrlEdge[m_numE];
	}

	if (p_storage->Read(&m_numL, sizeof(MxU16)) != SUCCESS) {
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
			if (ReadVector(p_storage, m_nodes[i]) != SUCCESS) {
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

		if (p_storage->Read(&length, sizeof(MxU8)) != SUCCESS) {
			return FAILURE;
		}

		if (length > 0) {
			m_structs[i].m_name = new char[length + 1];

			if (p_storage->Read(m_structs[i].m_name, length) != SUCCESS) {
				return FAILURE;
			}

			m_structs[i].m_name[length] = '\0';
		}

		if (p_storage->Read(&m_structs[i].m_flags, sizeof(MxU32)) != SUCCESS) {
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

		if (p_storage->Read(&edge.m_flags, sizeof(LegoU16)) != SUCCESS) {
			return FAILURE;
		}

		if (p_storage->Read(&s, sizeof(MxU16)) != SUCCESS) {
			return FAILURE;
		}
		assert(s < m_numN);
		edge.m_pointA = &m_nodes[s];

		if (p_storage->Read(&s, sizeof(MxU16)) != SUCCESS) {
			return FAILURE;
		}
		assert(s < m_numN);
		edge.m_pointB = &m_nodes[s];

		if (edge.m_flags & LegoOrientedEdge::c_hasFaceA) {
			if (p_storage->Read(&s, sizeof(MxU16)) != SUCCESS) {
				return FAILURE;
			}
			assert(s < m_numL);
			edge.m_faceA = &m_boundaries[s];

			if (p_storage->Read(&s, sizeof(MxU16)) != SUCCESS) {
				return FAILURE;
			}
			assert(s < m_numE);
			edge.m_ccwA = &m_edges[s];

			if (p_storage->Read(&s, sizeof(MxU16)) != SUCCESS) {
				return FAILURE;
			}
			assert(s < m_numE);
			edge.m_cwA = &m_edges[s];
		}

		if (edge.m_flags & LegoOrientedEdge::c_hasFaceB) {
			if (p_storage->Read(&s, sizeof(MxU16)) != SUCCESS) {
				return FAILURE;
			}
			assert(s < m_numL);
			edge.m_faceB = &m_boundaries[s];

			if (p_storage->Read(&s, sizeof(MxU16)) != SUCCESS) {
				return FAILURE;
			}
			assert(s < m_numE);
			edge.m_ccwB = &m_edges[s];

			if (p_storage->Read(&s, sizeof(MxU16)) != SUCCESS) {
				return FAILURE;
			}
			assert(s < m_numE);
			edge.m_cwB = &m_edges[s];
		}

		if (ReadVector(p_storage, edge.m_dir) != SUCCESS) {
			return FAILURE;
		}

		if (p_storage->Read(&edge.m_length, sizeof(float)) != SUCCESS) {
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
#ifdef BETA10
		Mx4DPointFloat unused;
#endif
		LegoPathBoundary& boundary = m_boundaries[i];
		MxU8 numE;
		MxU16 s;
		MxU8 j;

		if (p_storage->Read(&numE, sizeof(numE)) != SUCCESS) {
			return FAILURE;
		}

		assert(numE > 2);

		boundary.m_edgeNormals = new Mx4DPointFloat[numE];

		LegoOrientedEdge** edges = new LegoOrientedEdge*[numE];
		boundary.SetEdges(edges, numE);

		for (j = 0; j < numE; j++) {
			if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
				return FAILURE;
			}

			assert(s < m_numE);

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

		if (ReadVector(p_storage, boundary.m_up) != SUCCESS) {
			return FAILURE;
		}

		for (j = 0; j < numE; j++) {
			if (ReadVector(p_storage, boundary.m_edgeNormals[j]) != SUCCESS) {
				return FAILURE;
			}
		}

		if (ReadVector(p_storage, boundary.m_centerPoint) != SUCCESS) {
			return FAILURE;
		}

		if (p_storage->Read(&boundary.m_boundingRadius, sizeof(boundary.m_boundingRadius)) != SUCCESS) {
			return FAILURE;
		}

		if (p_storage->Read(&boundary.m_numTriggers, sizeof(boundary.m_numTriggers)) != SUCCESS) {
			return FAILURE;
		}

		if (boundary.m_numTriggers > 0) {
			boundary.m_direction = new Mx3DPointFloat;
			boundary.m_pathTrigger = new PathWithTrigger[boundary.m_numTriggers];

			for (j = 0; j < boundary.m_numTriggers; j++) {
				if (p_storage->Read(&s, sizeof(s)) != SUCCESS) {
					return FAILURE;
				}

				assert(s < m_numT);

				boundary.m_pathTrigger[j].m_pathStruct = &m_structs[s];

				if (p_storage->Read(&boundary.m_pathTrigger[j].m_data, sizeof(boundary.m_pathTrigger[j].m_data)) !=
					SUCCESS) {
					return FAILURE;
				}

				if (p_storage->Read(
						&boundary.m_pathTrigger[j].m_triggerLength,
						sizeof(boundary.m_pathTrigger[j].m_triggerLength)
					) != SUCCESS) {
					return FAILURE;
				}
			}

			if (ReadVector(p_storage, *boundary.m_direction) != SUCCESS) {
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

// FUNCTION: LEGO1 0x10048310
// FUNCTION: BETA10 0x100b8911
MxResult LegoPathController::FindPath(
	LegoPathEdgeContainer* p_grec,
	const Vector3& p_oldPosition,
	const Vector3& p_oldDirection,
	LegoPathBoundary* p_oldBoundary,
	const Vector3& p_newPosition,
	const Vector3& p_newDirection,
	LegoPathBoundary* p_newBoundary,
	LegoU8 p_mask,
	MxFloat* p_distance
)
{
	p_grec->m_position = p_newPosition;
	p_grec->m_direction = p_newDirection;
	p_grec->m_boundary = p_newBoundary;

	if (p_newBoundary == p_oldBoundary) {
		p_grec->SetPath(TRUE);
		return SUCCESS;
	}

	list<LegoBEWithMidpoint> boundaryList;
	list<LegoBEWithMidpoint>::iterator boundaryListIt;

	LegoBEWithMidpointSet boundarySet;
	LegoBEWithMidpointSet::iterator boundarySetItA;
	LegoBEWithMidpointSet::iterator boundarySetItB;

	LegoPathCtrlEdgeSet pathCtrlEdgeSet(m_pfsE);

	MxFloat minDistance = 999999.0f;

	p_grec->SetPath(FALSE);

	for (MxS32 i = 0; i < p_oldBoundary->GetNumEdges(); i++) {
		LegoPathCtrlEdge* edge = (LegoPathCtrlEdge*) p_oldBoundary->GetEdges()[i];

		if (edge->GetMask0x03()) {
			LegoPathBoundary* otherFace = (LegoPathBoundary*) edge->OtherFace(p_oldBoundary);

			if (otherFace != NULL && edge->BETA_1004a830(*otherFace, p_mask)) {
				if (p_newBoundary == otherFace) {
					float dist;
					if ((dist = edge->DistanceToMidpoint(p_oldPosition) + edge->DistanceToMidpoint(p_newPosition)) <
						minDistance) {
						minDistance = dist;
						p_grec->erase(p_grec->begin(), p_grec->end());
						p_grec->SetPath(TRUE);
						p_grec->push_back(LegoBoundaryEdge(edge, p_oldBoundary));
					}
				}
				else {
					boundaryList.push_back(
						LegoBEWithMidpoint(edge, p_oldBoundary, edge->DistanceToMidpoint(p_oldPosition))
					);
					boundarySet.insert(&boundaryList.back());
				}
			}
		}

		pathCtrlEdgeSet.erase(edge);
	}

	if (!p_grec->HasPath()) {
		while (pathCtrlEdgeSet.size() > 0) {
			LegoBEWithMidpoint edgeWithMidpoint;
			MxFloat minDist = 999999.0f;

			boundarySetItA = boundarySetItB = boundarySet.begin();

			if (boundarySetItB != boundarySet.end()) {
				boundarySetItB++;
			}

			while (boundarySetItA != boundarySet.end()) {
				MxU32 shouldRemove = TRUE;

				LegoOrientedEdge* e = (*boundarySetItA)->m_edge;
				LegoPathBoundary* b = (*boundarySetItA)->m_boundary;
				assert(e && b);

				LegoPathBoundary* bOther = (LegoPathBoundary*) e->OtherFace(b);
				assert(bOther);

				if (!e->BETA_1004a830(*bOther, p_mask)) {
					// This branch is empty, but present in the BETA - probably had comments only
				}
				else {
					if (bOther == p_newBoundary) {
						shouldRemove = FALSE;

						LegoBEWithMidpoint* pfs = *boundarySetItA;
						assert(pfs);

						float dist;
						if ((dist = pfs->m_edge->DistanceToMidpoint(p_newPosition) + pfs->m_distanceToMidpoint) <
							minDist) {
							edgeWithMidpoint.m_edge = NULL;
							minDist = dist;

							// TODO: Match
							if (dist < minDistance) {
								minDistance = dist;
								p_grec->erase(p_grec->begin(), p_grec->end());
								p_grec->SetPath(TRUE);

								do {
									p_grec->push_front(LegoBoundaryEdge(pfs->m_edge, pfs->m_boundary));
									pfs = pfs->m_next;
								} while (pfs != NULL);
							}
						}
					}
					else {
						for (MxS32 i = 0; i < bOther->GetNumEdges(); i++) {
							LegoPathCtrlEdge* edge = (LegoPathCtrlEdge*) bOther->GetEdges()[i];

							if (edge->GetMask0x03()) {
								if (pathCtrlEdgeSet.find(edge) != pathCtrlEdgeSet.end()) {
									shouldRemove = FALSE;

									float dist;
									if ((dist = edge->DistanceBetweenMidpoints(*e) +
												(*boundarySetItA)->m_distanceToMidpoint) < minDist) {
										minDist = dist;
										edgeWithMidpoint = LegoBEWithMidpoint(edge, bOther, *boundarySetItA, dist);
									}
								}
							}
						}
					}
				}

				if (shouldRemove) {
					boundarySet.erase(boundarySetItA);
				}

				if (boundarySetItB != boundarySet.end()) {
					boundarySetItA = boundarySetItB;
					boundarySetItB++;
				}
				else {
					break;
				}
			}

			if (edgeWithMidpoint.m_edge != NULL) {
				pathCtrlEdgeSet.erase(edgeWithMidpoint.m_edge);
				boundaryList.push_back(edgeWithMidpoint);
				boundarySet.insert(&boundaryList.back());
			}
			else {
				break;
			}
		}
	}

	if (p_grec->HasPath()) {
		if (p_grec->size() > 0) {
			LegoPathCtrlEdge* edge = p_grec->front().m_edge;

			if (edge->FUN_10048c40(p_oldPosition)) {
				p_grec->pop_front();
			}
		}

		if (p_grec->size() > 0) {
			LegoPathCtrlEdge* edge = p_grec->back().m_edge;

			if (edge->FUN_10048c40(p_newPosition)) {
				if (edge->OtherFace(p_grec->back().m_boundary) != NULL &&
					edge->OtherFace(p_grec->back().m_boundary)->IsEqual(p_newBoundary)) {
					p_grec->m_boundary = p_grec->back().m_boundary;
					p_grec->pop_back();
				}
			}
		}

		if (p_distance != NULL) {
			*p_distance = minDistance;
		}

		return SUCCESS;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x1004a240
// FUNCTION: BETA10 0x100b9160
MxS32 LegoPathController::GetNextPathEdge(
	LegoPathEdgeContainer& p_grec,
	Vector3& p_position,
	Vector3& p_direction,
	float p_f1,
	LegoOrientedEdge*& p_edge,
	LegoPathBoundary*& p_boundary
)
{
	if (p_grec.size() == 0) {
		p_position = p_grec.m_position;
		p_direction = p_grec.m_direction;
		p_boundary = p_grec.m_boundary;
		p_grec.SetPath(FALSE);
		return 1;
	}

	p_edge = p_grec.front().m_edge;
	p_boundary = p_grec.front().m_boundary;
	p_grec.pop_front();

	Mx3DPointFloat vec;
	p_position = *p_edge->CCWVertex(*p_boundary);
	p_position -= *p_edge->CWVertex(*p_boundary);
	p_position *= p_f1;
	p_position += *p_edge->CWVertex(*p_boundary);
	p_edge->GetFaceNormal(*p_boundary, vec);
	p_direction.EqualsCross(*p_boundary->GetUp(), vec);
	return 0;
}

// FUNCTION: LEGO1 0x1004a380
// FUNCTION: BETA10 0x100b957f
MxResult LegoPathController::FindIntersectionBoundary(
	Vector3& p_location,
	Vector3& p_direction,
	Mx3DPointFloat* p_coefficients,
	LegoPathBoundary*& p_boundary,
	MxFloat& p_apexParameter
)
{
	MxFloat originalApexParameter = p_apexParameter;
	Mx3DPointFloat intersectionPoint;
	MxU32 solutionNotFound = TRUE;

	for (MxS32 i = 0; i < m_numL; i++) {
		if (m_boundaries[i].m_flags & LegoPathBoundary::c_bit3) {
			continue;
		}

		LegoPathBoundary* b = &m_boundaries[i];
		Mx4DPointFloat* up = b->GetUp();
		float coeffADotUp = p_coefficients[0].Dot(p_coefficients[0], *up);

		if (coeffADotUp < 0.001 && coeffADotUp > -0.001) {
			continue;
		}

		float coeffBDotUp = p_coefficients[1].Dot(p_coefficients[1], *up);
		float coeffCDotUp = p_coefficients[2].Dot(p_coefficients[2], *up) + up->index_operator(3);
		float quadraticDiscriminant = coeffBDotUp * coeffBDotUp - coeffCDotUp * coeffADotUp * 4.0f;

		if (quadraticDiscriminant < -0.001) {
			continue;
		}

		if (quadraticDiscriminant < 0.0f) {
			quadraticDiscriminant = 0.0f;
		}
		else {
			quadraticDiscriminant = sqrt(quadraticDiscriminant);
		}

		float intersectionParameter = (quadraticDiscriminant - coeffBDotUp) / (coeffADotUp * 2.0f);
		float alternativeIntersectionParameter = (-quadraticDiscriminant - coeffBDotUp) / (coeffADotUp * 2.0f);

		if (!IsBetween(intersectionParameter, 0.0f, originalApexParameter)) {
			if (IsBetween(alternativeIntersectionParameter, 0.0f, originalApexParameter)) {
				intersectionParameter = alternativeIntersectionParameter;
			}
			else {
				continue;
			}
		}

		if (solutionNotFound ||
			BothSameComparison(intersectionParameter, p_apexParameter, 0.0f, originalApexParameter)) {
			Mx3DPointFloat tSqrA(p_coefficients[0]);

			tSqrA *= intersectionParameter * intersectionParameter;
			intersectionPoint = p_coefficients[1];
			intersectionPoint *= intersectionParameter;
			intersectionPoint += p_coefficients[2];
			intersectionPoint += tSqrA;

			assert(b->GetNumEdges() > 1);

			MxS32 j;
			for (j = b->GetNumEdges() - 1; j >= 0; j--) {
				Mx4DPointFloat* edgeNormal = b->GetEdgeNormal(j);

				if (intersectionPoint.Dot(*edgeNormal, intersectionPoint) + edgeNormal->index_operator(3) < -0.001) {
					break;
				}
			}

			if (j < 0) {
				Mx3DPointFloat direction(p_location);
				direction -= intersectionPoint;

				if (direction.Dot(direction, *up) >= 0.0f) {
					p_apexParameter = intersectionParameter;
					p_boundary = b;
					solutionNotFound = FALSE;
				}
			}
		}
	}

	if (solutionNotFound) {
		p_apexParameter = originalApexParameter;
		return FAILURE;
	}

	return SUCCESS;
}
