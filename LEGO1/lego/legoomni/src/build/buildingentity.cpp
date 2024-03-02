#include "buildingentity.h"

#include "legoomni.h"
#include "mxnotificationmanager.h"

// FUNCTION: LEGO1 0x10014e20
BuildingEntity::BuildingEntity()
{
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10015030
BuildingEntity::~BuildingEntity()
{
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x100150a0
MxLong BuildingEntity::Notify(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetType() == c_notificationType11) {
		return VTable0x50(p_param);
	}

	return 0;
}
