#include "mxparam.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxParam, 0xc);

// OFFSET: LEGO1 0x10010390
MxParam* MxParam::Clone()
{
  return new MxParam(m_type, m_sender);
}
