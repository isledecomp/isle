#include "helicopterstate.h"

// FUNCTION: LEGO1 0x1000e0b0
MxBool HelicopterState::VTable0x14()
{
	return FALSE;
}

// FUNCTION: LEGO1 0x1000e0c0
MxBool HelicopterState::SetFlag()
{
	this->m_unk0x8 = 0;
	return TRUE;
}
