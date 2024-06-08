#include "act2policestation.h"

#include "legoworld.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxnotificationparam.h"

DECOMP_SIZE_ASSERT(Act2PoliceStation, 0x68)

// FUNCTION: LEGO1 0x1004e0e0
MxLong Act2PoliceStation::Notify(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetType() == c_notificationClick) {
		NotificationManager()->Send(CurrentWorld(), MxNotificationParam(c_notificationType23, NULL));
		return 1;
	}

	return -1;
}
