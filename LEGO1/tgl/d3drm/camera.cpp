#include "impl.h"

using namespace TglImpl;

DECOMP_SIZE_ASSERT(Camera, 0x4);
DECOMP_SIZE_ASSERT(CameraImpl, 0x8);

// FUNCTION: LEGO1 0x100a36f0
void* CameraImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a3700
Result CameraImpl::SetTransformation(FloatMatrix4& matrix)
{
	D3DRMMATRIX4D helper;
	D3DRMMATRIX4D* pTransformation = Translate(matrix, helper);

	D3DVECTOR position;
	Result result;
	Result result2;

	result2 = ResultVal(m_data->GetPosition(0, &position));
	result = ResultVal(m_data->AddTransform(D3DRMCOMBINE_REPLACE, *pTransformation));
	// The did this second call just to assert on the return value
	result2 = ResultVal(m_data->GetPosition(0, &position));

	return result;
}
