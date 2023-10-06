#include "buildingentity.h"

#include "mxomni.h"

// OFFSET: LEGO1 0x10014e20
BuildingEntity::BuildingEntity()
{
  NotificationManager()->Register(this);
}

// OFFSET: LEGO1 0x10015030
BuildingEntity::~BuildingEntity()
{
  NotificationManager()->Unregister(this);
}
