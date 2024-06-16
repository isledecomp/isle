#include "isleactor.h"

#include "legoentity.h"
#include "legoworld.h"
#include "misc.h"
#include "mxnotificationparam.h"
#include "scripts.h"

DECOMP_SIZE_ASSERT(IsleActor, 0x7c)

// FUNCTION: LEGO1 0x1002c780
MxResult IsleActor::Create(MxDSAction& p_dsAction)
{
	MxResult result = LegoEntity::Create(p_dsAction);

	if (result == SUCCESS) {
		m_world = CurrentWorld();

		if (!m_world) {
			result = FAILURE;
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1002c7b0
MxLong IsleActor::Notify(MxParam& p_param)
{
	MxLong result = 0;

	switch (((MxNotificationParam&) p_param).GetNotification()) {
	case c_notificationType0:
		result = VTable0x6c();
		break;
	case c_notificationEndAction:
		result = HandleEndAction((MxEndActionNotificationParam&) p_param);
		break;
	case c_notificationButtonUp:
		result = HandleButtonUp((LegoControlManagerNotificationParam&) p_param);
		break;
	case c_notificationButtonDown:
		result = HandleButtonDown((LegoControlManagerNotificationParam&) p_param);
		break;
	case c_notificationClick:
		result = HandleClick();
		break;
	case c_notificationEndAnim:
		result = HandleEndAnim();
		break;
	case c_notificationPathStruct:
		result = HandlePathStruct((LegoPathStructNotificationParam&) p_param);
		break;
	}

	return result;
}
