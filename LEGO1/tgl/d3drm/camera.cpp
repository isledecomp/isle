#include "impl.h"

#include <assert.h>

using namespace TglImpl;

DECOMP_SIZE_ASSERT(Camera, 0x04);
DECOMP_SIZE_ASSERT(CameraImpl, 0x08);

// FUNCTION: LEGO1 0x100a36f0
// FUNCTION: BETA10 0x1016f2e0
void* CameraImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: BETA10 0x1016f390
inline Result CameraSetTransformation(IDirect3DRMFrame2* pCamera, FloatMatrix4& matrix)
{
	D3DRMMATRIX4D helper;
	D3DRMMATRIX4D* pTransformation = Translate(matrix, helper);

	D3DVECTOR position;
	Result result;
	Result result2;

	result2 = ResultVal(pCamera->GetPosition(0, &position));
	assert(Succeeded(result2));

	result = ResultVal(pCamera->AddTransform(D3DRMCOMBINE_REPLACE, *pTransformation));
	assert(Succeeded(result));

	result2 = ResultVal(pCamera->GetPosition(0, &position));
	assert(Succeeded(result2));

	return result;
}

// FUNCTION: LEGO1 0x100a3700
// FUNCTION: BETA10 0x1016f330
Result CameraImpl::SetTransformation(FloatMatrix4& matrix)
{
	assert(m_data);

	return CameraSetTransformation(m_data, matrix);
}
