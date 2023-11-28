#include "mxnotificationparam.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxNotificationParam, 0xc);

// FUNCTION: LEGO1 0x10010390
MxNotificationParam* MxNotificationParam::Clone()
{
	return new MxNotificationParam(m_type, m_sender);
}
