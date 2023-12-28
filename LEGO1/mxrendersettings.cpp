#include "mxrendersettings.h"

#include "decomp.h"

// FUNCTION: LEGO1 0x100ab2d0
MxU32 MxRenderSettings::operator=(const MxRenderSettings& p_settings)
{
	this->m_unk0x00 = p_settings.m_unk0x00;
	this->m_hwnd = p_settings.m_hwnd;
	this->m_directDraw = p_settings.m_directDraw;
	this->m_ddSurface1 = p_settings.m_ddSurface1;
	this->m_ddSurface2 = p_settings.m_ddSurface2;
	this->m_flags = p_settings.m_flags;
	this->m_unk0x18 = p_settings.m_unk0x18;
	this->m_flags2 = p_settings.m_flags2;
	this->m_direct3d = p_settings.m_direct3d;
	this->m_d3dDevice = p_settings.m_d3dDevice;
	return 1;
}
