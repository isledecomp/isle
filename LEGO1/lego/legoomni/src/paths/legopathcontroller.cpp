#include "legopathcontroller.h"

DECOMP_SIZE_ASSERT(LegoPathController, 0x40)

// STUB: LEGO1 0x10044f40
LegoPathController::LegoPathController()
{
	// TODO
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

// STUB: LEGO1 0x10045c20
// FUNCTION: BETA10 0x100b6d80
MxResult LegoPathController::FUN_10045c20(
	LegoPathActor* p_actor,
	const char* p_path,
	MxS32 p_src,
	float p_srcScale,
	MxS32 p_dest,
	float p_destScale
)
{
	return SUCCESS;
}

// STUB: LEGO1 0x10046770
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
