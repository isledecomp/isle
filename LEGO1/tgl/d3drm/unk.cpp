#include "impl.h"

using namespace TglImpl;

DECOMP_SIZE_ASSERT(Unk, 0x4);
DECOMP_SIZE_ASSERT(UnkImpl, 0x8);

// Inlined only
UnkImpl::~UnkImpl()
{
	if (m_data) {
		m_data->Release();
		m_data = NULL;
	}
}

// OFFSET: LEGO1 0x100a3830
void* UnkImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// OFFSET: LEGO1 0x100a3840 STUB
Result UnkImpl::SetMeshData(
	unsigned long p_faceCount,
	unsigned long p_vertexCount,
	const float (*p_positions)[3],
	const float (*p_normals)[3],
	const float (*p_textureCoordinates)[2],
	unsigned long p_vertexPerFaceCount,
	unsigned long* p_faceData
)
{
	return Error;
}

// OFFSET: LEGO1 0x100a3ae0
Result UnkImpl::GetBoundingBox(float p_min[3], float p_max[3])
{
	D3DRMBOX box;
	Result result = ResultVal(m_data->GetBox(&box));
	if (result == Success) {
		p_min[0] = box.min.x;
		p_min[1] = box.min.y;
		p_min[2] = box.min.z;
		p_max[0] = box.max.x;
		p_max[1] = box.max.y;
		p_max[2] = box.max.z;
	}
	return result;
}

// OFFSET: LEGO1 0x100a3b40
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
