#include "impl.h"

using namespace TglImpl;

DECOMP_SIZE_ASSERT(Unk, 0x04);
DECOMP_SIZE_ASSERT(UnkImpl, 0x08);

// FUNCTION: LEGO1 0x100a3830
void* UnkImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// STUB: LEGO1 0x100a3840
Result UnkImpl::SetMeshData(
	unsigned long faceCount,
	unsigned long vertexCount,
	const float (*pPositions)[3],
	const float (*pNormals)[3],
	const float (*pTextureCoordinates)[2],
	unsigned long vertexPerFaceCount,
	unsigned long* pFaceData
)
{
	return Error;
}

// FUNCTION: LEGO1 0x100a3ae0
Result UnkImpl::GetBoundingBox(float min[3], float max[3])
{
	D3DRMBOX box;
	Result result = ResultVal(m_data->GetBox(&box));
	if (result == Success) {
		min[0] = box.min.x;
		min[1] = box.min.y;
		min[2] = box.min.z;
		max[0] = box.max.x;
		max[1] = box.max.y;
		max[2] = box.max.z;
	}
	return result;
}

// FUNCTION: LEGO1 0x100a3b40
Unk* UnkImpl::Clone()
{
	UnkImpl* mesh = new UnkImpl();
	int ret = m_data->Clone(0, IID_IDirect3DRMMeshBuilder, (void**) &mesh->m_data);
	if (ret < 0) {
		delete mesh;
		mesh = NULL;
	}
	return mesh;
}
