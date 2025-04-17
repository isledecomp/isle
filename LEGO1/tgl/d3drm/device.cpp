#include "impl.h"

#include <assert.h>
#include <d3drmwin.h>

using namespace TglImpl;

// FUNCTION: LEGO1 0x100a2bf0
// FUNCTION: BETA10 0x1016ddf0
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

// FUNCTION: BETA10 0x1016e020
inline Result DeviceSetShadingModel(IDirect3DRMDevice2* pDevice, ShadingModel model)
{
	D3DRMRENDERQUALITY renderQuality = Translate(model);
	return ResultVal(pDevice->SetQuality(renderQuality));
}

// FUNCTION: LEGO1 0x100a2c30
// FUNCTION: BETA10 0x1016dfc0
Result DeviceImpl::SetShadingModel(ShadingModel model)
{
	assert(m_data);

	return DeviceSetShadingModel(m_data, model);
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

// FUNCTION: LEGO1 0x100a2ce0
void DeviceImpl::HandleActivate(WORD wParam)
{
	// Device argument is intentionally unused.
	IDirect3DRMWinDevice* winDevice;
	if (ResultVal(m_data->QueryInterface(IID_IDirect3DRMWinDevice, (LPVOID*) &winDevice))) {
		winDevice->HandleActivate(wParam);
		winDevice->Release();
	}
}

// FUNCTION: LEGO1 0x100a2d20
void DeviceImpl::HandlePaint(HDC p_dc)
{
	IDirect3DRMWinDevice* winDevice;
	if (SUCCEEDED(m_data->QueryInterface(IID_IDirect3DRMWinDevice, (LPVOID*) &winDevice))) {
		winDevice->HandlePaint(p_dc);
		winDevice->Release();
	}
}

// FUNCTION: LEGO1 0x100a2d60
Result DeviceImpl::Update()
{
	return ResultVal(m_data->Update());
}

// GLOBAL: LEGO1 0x100dd1d0
// IID_IDirect3DRMWinDevice
