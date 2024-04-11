#include "isleactor.h"

#include "legoentity.h"
#include "legoomni.h"
#include "legoworld.h"
#include "misc.h"
#include "mxnotificationparam.h"

DECOMP_SIZE_ASSERT(IsleActor, 0x7c)

// FUNCTION: LEGO1 0x1002c780
MxResult IsleActor::Create(MxDSAction& p_dsAction)
{
	MxResult ret = LegoEntity::Create(p_dsAction);

	if (ret == SUCCESS) {
		m_world = CurrentWorld();

		if (!m_world) {
			ret = FAILURE;
		}
	}

	return ret;
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
		result = HandleButtonUp((MxNotificationParam&) p_param);
		break;
	case c_notificationButtonDown:
		result = HandleButtonDown((MxNotificationParam&) p_param);
		break;
	case c_notificationType11:
		result = VTable0x68();
		break;
	case c_notificationType18:
		result = VTable0x70();
		break;
	case c_notificationType19:
		result = VTable0x80(p_param);
		break;
	}

	return result;
}
