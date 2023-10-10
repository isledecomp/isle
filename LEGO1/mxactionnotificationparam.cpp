#include "mxactionnotificationparam.h"

DECOMP_SIZE_ASSERT(MxActionNotificationParam, 0x14)
DECOMP_SIZE_ASSERT(MxEndActionNotificationParam, 0x14)

// OFFSET: LEGO1 0x100510c0
MxNotificationParam *MxActionNotificationParam::Clone()
{
  return new MxActionNotificationParam(this->m_type, this->m_sender, this->m_action, this->m_realloc);
}

// OFFSET: LEGO1 0x10051270
MxNotificationParam *MxEndActionNotificationParam::Clone()
{
  return new MxEndActionNotificationParam(MXSTREAMER_UNKNOWN, this->m_sender, this->m_action, this->m_realloc);
}
