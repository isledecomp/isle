// Declaration-record carrier (dial campaign, PRE): samples this translation
// unit's accumulated declaration state before the include block. [14 units]
class RkRqM0 {
	void m0() {}
};
class RkRqF0;
class RkRqF1;
class RkRqF2;
class RkRqF3;

// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
// session notes 2026-08-01); no authentic 1997 declaration is recoverable at
// this position. Neutral stand-in pending better evidence.
class MxUnkRecordTM {};
class MxUnkRecordTN {};
class MxUnkRecordTO {};

#include "mxactionnotificationparam.h"

DECOMP_SIZE_ASSERT(MxActionNotificationParam, 0x14)
DECOMP_SIZE_ASSERT(MxEndActionNotificationParam, 0x14)

// FUNCTION: LEGO1 0x100b0300
MxNotificationParam* MxStartActionNotificationParam::Clone() const
{
	return new MxStartActionNotificationParam(
		c_notificationStartAction,
		this->m_sender,
		this->m_action,
		this->m_realloc
	);
}

// FUNCTION: LEGO1 0x100b04f0
MxNotificationParam* MxType4NotificationParam::Clone() const
{
	return new MxType4NotificationParam(this->m_sender, this->m_action, this->m_unk0x14);
}
