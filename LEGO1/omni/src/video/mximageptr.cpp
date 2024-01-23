#include "mximageptr.h"

DECOMP_SIZE_ASSERT(MxImagePtr, 0x4)

// FUNCTION: LEGO1 0x10098fb0
MxImagePtr::MxImagePtr()
{
	m_pImage = new MxImage();
}
// FUNCTION: LEGO1 0x10099030
MxImagePtr::~MxImagePtr()
{
	if (m_pImage)
		delete m_pImage;
}
// FUNCTION: LEGO1 0x10099050
MxResult MxImagePtr::Read(LegoStream* p_stream, MxU32 p_square)
{
	return m_pImage->Read(p_stream, p_square);
}
// FUNCTION: LEGO1 0x10099070
MxResult MxImagePtr::Write(LegoStream* p_stream)
{
	return m_pImage->Write(p_stream);
}
