#include "legovehiclebuildstate.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(LegoVehicleBuildState, 0x50)

// FUNCTION: LEGO1 0x10025f30
LegoVehicleBuildState::LegoVehicleBuildState(char* p_classType)
{
	this->m_className = p_classType;
	this->m_unk0x4c = 0;
	this->m_unk0x4d = 0;
	this->m_unk0x4e = 0;
	this->m_placedPartCount = 0;
}

// STUB: LEGO1 0x10026120
MxResult LegoVehicleBuildState::VTable0x1c(LegoFile* p_legoFile)
{
	// TODO
	return SUCCESS;
}
