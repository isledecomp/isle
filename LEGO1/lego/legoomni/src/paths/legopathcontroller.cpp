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

	if (m_numT > 0 && FUN_10047b30(p_storage) != SUCCESS) {
		return FAILURE;
	}

	if (m_numN > 0) {
		for (MxS32 i = 0; i < m_numN; i++) {
			if (FUN_100482b0(p_storage, m_unk0x10[i]) != SUCCESS) {
				return FAILURE;
			}
		}
	}

	if (m_numE > 0 && FUN_10047c10(p_storage) != SUCCESS) {
		return FAILURE;
	}

	if (m_numL > 0 && FUN_10047e90(p_storage) != SUCCESS) {
		return FAILURE;
	}

	for (MxS32 j = 0; j < m_numE; j++) {
		m_pfsE.insert(&m_unk0x0c[j]);
	}

	return SUCCESS;
}

// STUB: LEGO1 0x10047b30
// FUNCTION: BETA10 0x100b7cd6
MxResult LegoPathController::FUN_10047b30(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10047c10
// FUNCTION: BETA10 0x1100b7df3
MxResult LegoPathController::FUN_10047c10(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10047e90
// FUNCTION: BETA10 0x100b8293
MxResult LegoPathController::FUN_10047e90(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x100482b0
// FUNCTION: BETA10 0x100b8864
MxResult LegoPathController::FUN_100482b0(LegoStorage* p_storage, Mx3DPointFloat&)
{
	// TODO
	return SUCCESS;
}
