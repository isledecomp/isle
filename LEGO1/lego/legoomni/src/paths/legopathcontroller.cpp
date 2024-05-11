#include "legopathcontroller.h"

#include "mxmisc.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(LegoPathController, 0x40)

// FUNCTION: LEGO1 0x10044f40
// FUNCTION: BETA10 0x100b6860
LegoPathController::LegoPathController()
{
	m_unk0x08 = NULL;
	m_unk0x0c = 0;
	m_unk0x10 = 0;
	m_unk0x14 = 0;
	m_numL = 0;
	m_numE = 0;
	m_numN = 0;
	m_numT = 0;
}

// STUB: LEGO1 0x10045880
void LegoPathController::VTable0x14(MxU8* p_data, Vector3& p_location, MxAtomId& p_trigger)
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
