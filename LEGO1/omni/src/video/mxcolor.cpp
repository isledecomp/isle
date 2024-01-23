#include "mxcolor.h"

DECOMP_SIZE_ASSERT(MxColor, 0x3)

// FUNCTION: LEGO1 0x100994c0
MxColor::MxColor()
{
	m_color[0] = 0;
	m_color[1] = 0;
	m_color[2] = 0;
}

// FUNCTION: LEGO1 0x100994d0
MxResult MxColor::Read(LegoStream* p_stream)
{
	MxResult result;
	if ((result = p_stream->Read(m_color, 1)) != SUCCESS)
		return result;
	if ((result = p_stream->Read(m_color + 1, 1)) != SUCCESS)
		return result;
	return (result = p_stream->Read(m_color + 2, 1)) != SUCCESS ? result : SUCCESS;
}

// FUNCTION: LEGO1 0x10099520
MxResult MxColor::Write(LegoStream* p_stream)
{
	MxResult result;
	if ((result = p_stream->Write(m_color, 1)) != SUCCESS)
		return result;
	if ((result = p_stream->Write(m_color + 1, 1)) != SUCCESS)
		return result;
	return (result = p_stream->Write(m_color + 2, 1)) != SUCCESS ? result : SUCCESS;
}
