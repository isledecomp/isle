#include "mxactionnotificationparam.h"

DECOMP_SIZE_ASSERT(MxActionNotificationParam, 0x14)
DECOMP_SIZE_ASSERT(MxEndActionNotificationParam, 0x14)

// FUNCTION: LEGO1 0x100b0300
MxNotificationParam* MxStartActionNotificationParam::Clone()
{
	return new MxStartActionNotificationParam(
		c_notificationStartAction,
		this->m_sender,
		this->m_action,
		this->m_realloc
	);
}

// FUNCTION: LEGO1 0x100b04f0
MxNotificationParam* MxType4NotificationParam::Clone()
{
	return new MxType4NotificationParam(this->m_sender, this->m_action, this->m_unk0x14);
}
