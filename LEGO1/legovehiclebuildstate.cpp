#include "legovehiclebuildstate.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(LegoVehicleBuildState, 0x50); // 1000acd7
DECOMP_SIZE_ASSERT(LegoVehicleBuildState::UnkStruct, 0xc);

// OFFSET: LEGO1 0x10017c00
LegoVehicleBuildState::UnkStruct::UnkStruct()
{
	m_unk04 = 0;
	m_unk00 = 0;
	m_unk06 = 0;
	m_unk08 = 0;
}

// OFFSET: LEGO1 0x10025f30
LegoVehicleBuildState::LegoVehicleBuildState(char* p_classType)
{
	this->m_className = p_classType;
	this->m_unk4c = 0;
	this->m_unk4d = 0;
	this->m_unk4e = 0;
	this->m_placedPartCount = 0;
}
