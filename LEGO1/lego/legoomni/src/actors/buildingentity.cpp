#include "buildingentity.h"

#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxnotificationparam.h"

DECOMP_SIZE_ASSERT(BuildingEntity, 0x68)

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
// FUNCTION: BETA10 0x10024e37
MxLong BuildingEntity::Notify(MxParam& p_param)
{
	MxNotificationParam& param = (MxNotificationParam&) p_param;

	if (param.GetNotification() == c_notificationClick) {
		return HandleClick((LegoEventNotificationParam&) p_param);
	}

	return 0;
}
