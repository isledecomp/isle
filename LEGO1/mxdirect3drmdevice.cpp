#include "mxdirect3drmdevice.h"

#include "d3drmwin.h"
#include "decomp.h"

DECOMP_SIZE_ASSERT(IMxDirect3DRMDevice, 0x4);
DECOMP_SIZE_ASSERT(MxDirect3DRMDevice, 0x8);

// OFFSET: LEGO1 0x100a2bf0
IUnknown** MxDirect3DRMDevice::GetHandle()
{
	return (IUnknown**) &m_pD3DRMDevice;
}

// OFFSET: LEGO1 0x100a2c00
int MxDirect3DRMDevice::GetWidth()
{
	return m_pD3DRMDevice->GetWidth();
}

// OFFSET: LEGO1 0x100a2c10
int MxDirect3DRMDevice::GetHeight()
{
	return m_pD3DRMDevice->GetHeight();
}

// OFFSET: LEGO1 0x100a2c20
int MxDirect3DRMDevice::unknown1()
{
	return 1;
}

// Matching behavior, codegen differs in register alloc and timing of access.
// OFFSET: LEGO1 0x100a2c30
int MxDirect3DRMDevice::SetQuality(MxDirect3DRMDeviceQuality p_quality)
{
	D3DRMRENDERQUALITY quality;
	switch (p_quality) {
	case Wireframe:
		quality = D3DRMRENDER_WIREFRAME;
		break;
	case UnlitFlat:
		quality = D3DRMRENDER_UNLITFLAT;
		break;
	case Flat:
		quality = D3DRMRENDER_FLAT;
		break;
	case Gouraud:
		quality = D3DRMRENDER_GOURAUD;
		break;
	case Phong:
		quality = D3DRMRENDER_PHONG;
		break;
	default:
		quality = D3DRMRENDER_FLAT;
	}
	return SUCCEEDED(m_pD3DRMDevice->SetQuality(quality));
}

// OFFSET: LEGO1 0x100a2ca0
int MxDirect3DRMDevice::SetShades(MxU32 p_shades)
{
	return SUCCEEDED(m_pD3DRMDevice->SetShades(p_shades));
}

// OFFSET: LEGO1 0x100a2cc0
int MxDirect3DRMDevice::SetDither(int p_dither)
{
	return SUCCEEDED(m_pD3DRMDevice->SetDither(p_dither));
}

// OFFSET: LEGO1 0x100a2d60
int MxDirect3DRMDevice::Update()
{
	return SUCCEEDED(m_pD3DRMDevice->Update());
}

// Probably wrong, not sure what's going on in this method.
// OFFSET: LEGO1 0x100a2ce0
void MxDirect3DRMDevice::InitFromD3D()
{
	IDirect3DRMWinDevice* winDevice;
	if (SUCCEEDED(m_pD3DRMDevice->QueryInterface(IID_IDirect3DRMWinDevice, (LPVOID*) &winDevice))) {
		m_pD3DRMDevice->InitFromD3D((LPDIRECT3D) &winDevice, (LPDIRECT3DDEVICE) m_pD3DRMDevice);
		winDevice->Release();
	}
}

// Really don't know what's going on here. Seems it will call down to Init
// but the decomp suggests it otherwise looks the same as InitFromD3D but Init
// takes widly different parameters.
// OFFSET: LEGO1 0x100a2d20
void MxDirect3DRMDevice::Init()
{
	IDirect3DRMWinDevice* winDevice;
	if (SUCCEEDED(m_pD3DRMDevice->QueryInterface(IID_IDirect3DRMWinDevice, (LPVOID*) &winDevice))) {
		// m_pD3DRMDevice->Init();
		winDevice->Release();
	}
}
