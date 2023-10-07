#include "buildingentity.h"

#include "mxomni.h"

// OFFSET: LEGO1 0x10014e20
BuildingEntity::BuildingEntity()
{
  // this->m_vec1.m_data = this->m_vec1.storage;
  // this->m_vec2.m_data = this->m_vec2.storage;
  // this->m_vec3.m_data = this->m_vec3.storage;
  this->m_mxEntityId = -1;
  Reset();
  NotificationManager()->Register(this);
}

// OFFSET: LEGO1 0x10015030
BuildingEntity::~BuildingEntity()
{
  NotificationManager()->Unregister(this);
}
