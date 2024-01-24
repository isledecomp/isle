#include "legostate.h"

DECOMP_SIZE_ASSERT(LegoState, 0x08);

// FUNCTION: LEGO1 0x10005f40
LegoState::~LegoState()
{
}

// FUNCTION: LEGO1 0x10005f90
MxBool LegoState::VTable0x14()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x10005fa0
MxBool LegoState::SetFlag()
{
	return FALSE;
}

// FUNCTION: LEGO1 0x10005fb0
MxResult LegoState::VTable0x1c(LegoFile* p_legoFile)
{
	if (p_legoFile->IsWriteMode()) {
		p_legoFile->FUN_10006030(this->ClassName());
	}
	return SUCCESS;
}
