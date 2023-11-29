#include "impl.h"

#include <d3drmwin.h>

using namespace TglImpl;

// Inlined only
DeviceImpl::~DeviceImpl()
{
	if (m_data) {
		m_data->Release();
		m_data = NULL;
	}
}

// OFFSET: LEGO1 0x100a2bf0
void* DeviceImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// OFFSET: LEGO1 0x100a2c00
unsigned long DeviceImpl::GetWidth()
{
	return m_data->GetWidth();
}

// OFFSET: LEGO1 0x100a2c10
unsigned long DeviceImpl::GetHeight()
{
	return m_data->GetHeight();
}

// OFFSET: LEGO1 0x100a2c20
Result DeviceImpl::SetColorModel(ColorModel)
{
	return Success;
}

// OFFSET: LEGO1 0x100a2c30
Result DeviceImpl::SetShadingModel(ShadingModel p_model)
{
	// Doesn't match well even though we know this is exactly
	// the original code thanks to the jump table.
	D3DRMRENDERQUALITY renderQuality = Translate(p_model);
	return ResultVal(m_data->SetQuality(renderQuality));
}

// OFFSET: LEGO1 0x100a2ca0
Result DeviceImpl::SetShadeCount(unsigned long p_shadeCount)
{
	return ResultVal(m_data->SetShades(p_shadeCount));
}

// OFFSET: LEGO1 0x100a2cc0
Result DeviceImpl::SetDither(int p_dither)
{
	return ResultVal(m_data->SetDither(p_dither));
}

// OFFSET: LEGO1 0x100a2d60
Result DeviceImpl::Update()
{
	return ResultVal(m_data->Update());
}

// Probably wrong, not sure what's going on in this method.
// OFFSET: LEGO1 0x100a2ce0
void DeviceImpl::InitFromD3DDevice(Device*)
{
	// Device argument is intentionally unused.
	IDirect3DRMWinDevice* winDevice;
	if (ResultVal(m_data->QueryInterface(IID_IDirect3DRMWinDevice, (LPVOID*) &winDevice))) {
		m_data->InitFromD3D((LPDIRECT3D) &winDevice, (LPDIRECT3DDEVICE) m_data);
		winDevice->Release();
	}
}

// Really don't know what's going on here. Seems it will call down to Init
// but the decomp suggests it otherwise looks the same as InitFromD3D but Init
// takes widly different parameters.
// OFFSET: LEGO1 0x100a2d20
void DeviceImpl::InitFromWindowsDevice(Device*)
{
	// Device argument is intentionally unused.
	IDirect3DRMWinDevice* winDevice;
	if (SUCCEEDED(m_data->QueryInterface(IID_IDirect3DRMWinDevice, (LPVOID*) &winDevice))) {
		// m_data->Init(??);
		winDevice->Release();
	}
}
