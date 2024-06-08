#include "mxvideoparamflags.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxVideoParamFlags, 0x02)

// FUNCTION: LEGO1 0x100bec40
// FUNCTION: BETA10 0x1012dadb
MxVideoParamFlags::MxVideoParamFlags()
{
	m_flags1.m_bit0 = FALSE; // FullScreen
	m_flags1.m_bit1 = FALSE; // FlipSurfaces
	m_flags1.m_bit2 = FALSE; // BackBuffers
	m_flags1.m_bit3 = FALSE;
	m_flags1.m_bit4 = FALSE;
	m_flags1.m_bit5 = FALSE; // 16Bit
	m_flags1.m_bit6 = TRUE;  // WideViewAngle
	m_flags1.m_bit7 = TRUE;

	m_flags2.m_bit1 = TRUE;
}
