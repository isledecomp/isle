#include "legovehiclebuildstate.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(LegoVehicleBuildState, 0x50); // 1000acd7
DECOMP_SIZE_ASSERT(LegoVehicleBuildState::UnkStruct, 0xc);

// OFFSET: LEGO1 0x10025f30
LegoVehicleBuildState::LegoVehicleBuildState(char* p_classType)
{
  this->m_className = p_classType;
  this->m_unk2 = 0;
  this->m_unk3 = 0;
  this->m_unk4 = 0;
  this->m_placedPartCount = 0;
}

// OFFSET: LEGO1 10017c00
LegoVehicleBuildState::UnkStruct::UnkStruct()
{
  m_unk1 = 0;
  m_unk0 = 0;
  m_unk2 = 0;
  m_unk3 = 0;
}
