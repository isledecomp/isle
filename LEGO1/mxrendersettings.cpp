#include "mxrendersettings.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxRenderSettings, 0x28)

// FUNCTION: LEGO1 0x100ab2d0
MxU32 MxRenderSettings::CopyFrom(MxRenderSettings& p_dest, const MxRenderSettings& p_src)
{
	p_dest.m_unk0x00 = p_src.m_unk0x00;
	p_dest.m_hwnd = p_src.m_hwnd;
	p_dest.m_directDraw = p_src.m_directDraw;
	p_dest.m_ddSurface1 = p_src.m_ddSurface1;
	p_dest.m_ddSurface2 = p_src.m_ddSurface2;
	p_dest.m_flags = p_src.m_flags;
	p_dest.m_unk0x18 = p_src.m_unk0x18;
	p_dest.m_flags2 = p_src.m_flags2;
	p_dest.m_direct3d = p_src.m_direct3d;
	p_dest.m_d3dDevice = p_src.m_d3dDevice;
	return 1;
}
