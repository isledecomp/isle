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

// FUNCTION: BETA10 0x1016dea0
inline unsigned long DeviceGetWidth(IDirect3DRMDevice2* pDevice)
{
	return pDevice->GetWidth();
}

// FUNCTION: LEGO1 0x100a2c00
// FUNCTION: BETA10 0x1016de40
unsigned long DeviceImpl::GetWidth()
{
	assert(m_data);

	return DeviceGetWidth(m_data);
}

// FUNCTION: BETA10 0x1016df20
inline unsigned long DeviceGetHeight(IDirect3DRMDevice2* pDevice)
{
	return pDevice->GetHeight();
}

// FUNCTION: LEGO1 0x100a2c10
// FUNCTION: BETA10 0x1016dec0
unsigned long DeviceImpl::GetHeight()
{
	assert(m_data);

	return DeviceGetHeight(m_data);
}

// FUNCTION: BETA10 0x1016dfa0
inline Result DeviceSetColorModel(IDirect3DRMDevice2* pDevice, ColorModel)
{
	return Success;
}

// FUNCTION: LEGO1 0x100a2c20
// FUNCTION: BETA10 0x1016df40
Result DeviceImpl::SetColorModel(ColorModel p_model)
{
	assert(m_data);

	return DeviceSetColorModel(m_data, p_model);
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

// FUNCTION: BETA10 0x1016e140
inline Result DeviceSetShadeCount(IDirect3DRMDevice2* pDevice, unsigned long shadeCount)
{
	return ResultVal(pDevice->SetShades(shadeCount));
}

// FUNCTION: LEGO1 0x100a2ca0
// FUNCTION: BETA10 0x1016e0e0
Result DeviceImpl::SetShadeCount(unsigned long shadeCount)
{
	assert(m_data);

	return DeviceSetShadeCount(m_data, shadeCount);
}

// FUNCTION: BETA10 0x1016e1d0
inline Result DeviceSetDither(IDirect3DRMDevice2* pDevice, int dither)
{
	return ResultVal(pDevice->SetDither(dither));
}

// FUNCTION: LEGO1 0x100a2cc0
// FUNCTION: BETA10 0x1016e170
Result DeviceImpl::SetDither(int dither)
{
	assert(m_data);

	return DeviceSetDither(m_data, dither);
}

// FUNCTION: BETA10 0x1016e260
inline void DeviceHandleActivate(IDirect3DRMDevice2* pDevice, WORD wParam)
{
	IDirect3DRMWinDevice* winDevice;

	Result result = ResultVal(pDevice->QueryInterface(IID_IDirect3DRMWinDevice, (LPVOID*) &winDevice));
	if (Succeeded(result)) {
		winDevice->HandleActivate(wParam);
		int refCount = winDevice->Release();
		assert(refCount == 1);
	}
}

// FUNCTION: LEGO1 0x100a2ce0
// FUNCTION: BETA10 0x1016e200
void DeviceImpl::HandleActivate(WORD wParam)
{
	assert(m_data);

	DeviceHandleActivate(m_data, wParam);
}

// FUNCTION: BETA10 0x1016e360
inline void DeviceHandlePaint(IDirect3DRMDevice2* pDevice, void* p_data)
{
	IDirect3DRMWinDevice* winDevice;

	Result result = ResultVal(pDevice->QueryInterface(IID_IDirect3DRMWinDevice, (LPVOID*) &winDevice));
	if (Succeeded(result)) {
		HDC hdc = (HDC) p_data;
		winDevice->HandlePaint(hdc);
		int refCount = winDevice->Release();
		assert(refCount == 1);
	}
}

// FUNCTION: LEGO1 0x100a2d20
// FUNCTION: BETA10 0x1016e300
void DeviceImpl::HandlePaint(void* p_data)
{
	assert(m_data);

	DeviceHandlePaint(m_data, p_data);
}

// FUNCTION: BETA10 0x1016e460
inline Result DeviceUpdate(IDirect3DRMDevice2* pDevice)
{
	return ResultVal(pDevice->Update());
}

// FUNCTION: LEGO1 0x100a2d60
// FUNCTION: BETA10 0x1016e400
Result DeviceImpl::Update()
{
	assert(m_data);

	return DeviceUpdate(m_data);
}

// GLOBAL: LEGO1 0x100dd1d0
// GLOBAL: BETA10 0x101c30b0
// IID_IDirect3DRMWinDevice
