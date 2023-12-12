#include "impl.h"

#include <d3drmwin.h>

using namespace TglImpl;

// FUNCTION: LEGO1 0x100a2bf0
void* DeviceImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a2c00
unsigned long DeviceImpl::GetWidth()
{
	return m_data->GetWidth();
}

// FUNCTION: LEGO1 0x100a2c10
unsigned long DeviceImpl::GetHeight()
{
	return m_data->GetHeight();
}

// FUNCTION: LEGO1 0x100a2c20
Result DeviceImpl::SetColorModel(ColorModel)
{
	return Success;
}

// FUNCTION: LEGO1 0x100a2c30
Result DeviceImpl::SetShadingModel(ShadingModel model)
{
	// Doesn't match well even though we know this is exactly
	// the original code thanks to the jump table.
	D3DRMRENDERQUALITY renderQuality = Translate(model);
	return ResultVal(m_data->SetQuality(renderQuality));
}

// FUNCTION: LEGO1 0x100a2ca0
Result DeviceImpl::SetShadeCount(unsigned long shadeCount)
{
	return ResultVal(m_data->SetShades(shadeCount));
}

// FUNCTION: LEGO1 0x100a2cc0
Result DeviceImpl::SetDither(int dither)
{
	return ResultVal(m_data->SetDither(dither));
}

// Probably wrong, not sure what's going on in this method.
// FUNCTION: LEGO1 0x100a2ce0
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
// FUNCTION: LEGO1 0x100a2d20
void DeviceImpl::InitFromWindowsDevice(Device*)
{
	// Device argument is intentionally unused.
	IDirect3DRMWinDevice* winDevice;
	if (SUCCEEDED(m_data->QueryInterface(IID_IDirect3DRMWinDevice, (LPVOID*) &winDevice))) {
		// m_data->Init(??);
		winDevice->Release();
	}
}

// FUNCTION: LEGO1 0x100a2d60
Result DeviceImpl::Update()
{
	return ResultVal(m_data->Update());
}
