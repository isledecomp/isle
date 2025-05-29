#include "impl.h"

#include <assert.h>

using namespace TglImpl;

DECOMP_SIZE_ASSERT(Light, 0x04);
DECOMP_SIZE_ASSERT(LightImpl, 0x08);

// FUNCTION: LEGO1 0x100a3770
// FUNCTION: BETA10 0x1016f630
void* LightImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: BETA10 0x1016f6e0
inline Result LightSetTransformation(IDirect3DRMFrame2* pLight, FloatMatrix4& matrix)
{
	D3DRMMATRIX4D helper;
	D3DRMMATRIX4D* d3dMatrix = Translate(matrix, helper);
	return ResultVal(pLight->AddTransform(D3DRMCOMBINE_REPLACE, *d3dMatrix));
}

// FUNCTION: LEGO1 0x100a3780
// FUNCTION: BETA10 0x1016f680
Result LightImpl::SetTransformation(FloatMatrix4& matrix)
{
	assert(m_data);

	return LightSetTransformation(m_data, matrix);
}

// FUNCTION: BETA10 0x1016f860
inline Result LightSetColor(IDirect3DRMFrame2* pLight, float r, float g, float b)
{
	IDirect3DRMLightArray* lights;
	IDirect3DRMLight* light;
	Result result = ResultVal(pLight->GetLights(&lights));
	assert(Succeeded(result));
	assert(lights->GetSize() == 1);

	result = ResultVal(lights->GetElement(0, &light));
	assert(Succeeded(result));

	return ResultVal(light->SetColorRGB(r, g, b));
}

// FUNCTION: LEGO1 0x100a37e0
// FUNCTION: BETA10 0x1016f7f0
Result LightImpl::SetColor(float r, float g, float b)
{
	assert(m_data);

	return LightSetColor(m_data, r, g, b);
}
