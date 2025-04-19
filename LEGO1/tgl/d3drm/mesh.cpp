#include "impl.h"

#include <assert.h>

using namespace TglImpl;

DECOMP_SIZE_ASSERT(D3DRMVERTEX, 0x24);

DECOMP_SIZE_ASSERT(Mesh, 0x04);
DECOMP_SIZE_ASSERT(MeshImpl, 0x08);

// FUNCTION: LEGO1 0x100a3ed0
// FUNCTION: BETA10 0x101704d0
void* MeshImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a3ee0
Result MeshImpl::SetColor(float r, float g, float b, float a)
{
	// The first instruction makes no sense here:
	// cmp dword ptr [esp + 0x10], 0
	// This compares a, which we know is a float because it immediately
	// gets passed into D3DRMCreateColorRGBA, but does the comparison
	// as though it's an int??
	if (*reinterpret_cast<int*>(&a) > 0) {
		D3DCOLOR color = D3DRMCreateColorRGBA(r, g, b, a);
		return ResultVal(m_data->groupMesh->SetGroupColor(m_data->groupIndex, color));
	}
	else {
		return ResultVal(m_data->groupMesh->SetGroupColorRGB(m_data->groupIndex, r, g, b));
	}
}

// FUNCTION: LEGO1 0x100a3f50
Result MeshImpl::SetTexture(const Texture* pTexture)
{
	IDirect3DRMTexture* texture = pTexture ? static_cast<const TextureImpl*>(pTexture)->ImplementationData() : NULL;
	return ResultVal(m_data->groupMesh->SetGroupTexture(m_data->groupIndex, texture));
}

// FUNCTION: LEGO1 0x100a3f80
Result MeshImpl::SetTextureMappingMode(TextureMappingMode mode)
{
	if (mode == PerspectiveCorrect) {
		return ResultVal(m_data->groupMesh->SetGroupMapping(m_data->groupIndex, D3DRMMAP_PERSPCORRECT));
	}
	else {
		return ResultVal(m_data->groupMesh->SetGroupMapping(m_data->groupIndex, 0));
	}
}

// FUNCTION: BETA10 0x10170750
inline Result MeshSetShadingModel(MeshImpl::MeshData* pMesh, ShadingModel model)
{
	D3DRMRENDERQUALITY mode = Translate(model);
	return ResultVal(pMesh->groupMesh->SetGroupQuality(pMesh->groupIndex, mode));
}

// FUNCTION: LEGO1 0x100a3fc0
// FUNCTION: BETA10 0x101706f0
Result MeshImpl::SetShadingModel(ShadingModel model)
{
	assert(m_data);
	return MeshSetShadingModel(m_data, model);
}

// FUNCTION: BETA10 0x101714e0
inline Result MeshDeepClone(MeshImpl::MeshData* pSource, MeshImpl::MeshData*& rpTarget, IDirect3DRMMesh* pMesh)
{
	rpTarget = new MeshImpl::MeshData();
	rpTarget->groupMesh = pMesh;

	// Query information from old group
	DWORD dataSize;
	unsigned int vcount, fcount, vperface;

	Result result =
		ResultVal(pSource->groupMesh->GetGroup(pSource->groupIndex, &vcount, &fcount, &vperface, &dataSize, NULL));
	assert(Succeeded(result));

	unsigned int* faceBuffer = new unsigned int[dataSize];
	result =
		ResultVal(pSource->groupMesh->GetGroup(pSource->groupIndex, &vcount, &fcount, &vperface, &dataSize, faceBuffer)
		);
	assert(Succeeded(result));

	// We expect vertex to be sized 0x24, checked at start of file.
	D3DRMVERTEX* vertexBuffer = new D3DRMVERTEX[vcount];
	result = ResultVal(pSource->groupMesh->GetVertices(pSource->groupIndex, 0, vcount, vertexBuffer));
	assert(Succeeded(result));

	LPDIRECT3DRMTEXTURE textureRef;
	result = ResultVal(pSource->groupMesh->GetGroupTexture(pSource->groupIndex, &textureRef));
	assert(Succeeded(result));

	D3DRMMAPPING mapping = pSource->groupMesh->GetGroupMapping(pSource->groupIndex);
	D3DRMRENDERQUALITY quality = pSource->groupMesh->GetGroupQuality(pSource->groupIndex);
	D3DCOLOR color = pSource->groupMesh->GetGroupColor(pSource->groupIndex);

	// Push information to new group
	D3DRMGROUPINDEX index;
	result = ResultVal(pMesh->AddGroup(vcount, fcount, 3, faceBuffer, &index));
	assert(Succeeded(result));

	rpTarget->groupIndex = index;
	result = ResultVal(pMesh->SetVertices(index, 0, vcount, vertexBuffer));
	assert(Succeeded(result));

	result = ResultVal(pMesh->SetGroupTexture(index, textureRef));
	assert(Succeeded(result));

	result = ResultVal(pMesh->SetGroupMapping(index, mapping));
	assert(Succeeded(result));

	result = ResultVal(pMesh->SetGroupQuality(index, quality));
	assert(Succeeded(result));

	result = ResultVal(pMesh->SetGroupColor(index, color));
	assert(Succeeded(result));

	// Cleanup
	if (faceBuffer) {
		delete[] faceBuffer;
	}

	if (vertexBuffer) {
		delete[] vertexBuffer;
	}

	return result;
}

// FUNCTION: BETA10 0x10171360
inline Mesh* MeshImpl::DeepClone(const MeshBuilderImpl& rMesh)
{
	assert(m_data);
	assert(rMesh.ImplementationData());

	MeshImpl* clone = new MeshImpl();
	assert(!clone->ImplementationData());

	if (!MeshDeepClone(m_data, clone->ImplementationData(), rMesh.ImplementationData())) {
		delete clone;
		clone = NULL;
	}

	return clone;
}

// FUNCTION: LEGO1 0x100a4030
// FUNCTION: BETA10 0x101707a0
Mesh* MeshImpl::DeepClone(MeshBuilder* pMesh)
{
	assert(m_data);
	assert(pMesh);

	return DeepClone(*static_cast<MeshBuilderImpl*>(pMesh));
}

// FUNCTION: LEGO1 0x100a4240
Mesh* MeshImpl::ShallowClone(MeshBuilder* pMeshBuilder)
{
	MeshImpl* newGroup = new MeshImpl();
	MeshData* newData = new MeshData();
	newGroup->m_data = newData;
	if (newData) {
		newData->groupIndex = m_data->groupIndex;
		newData->groupMesh = static_cast<MeshBuilderImpl*>(pMeshBuilder)->ImplementationData();
	}
	else {
		delete newGroup;
		newGroup = NULL;
	}
	return newGroup;
}

// FUNCTION: LEGO1 0x100a4330
Result MeshImpl::GetTexture(Texture*& rpTexture)
{
	IDirect3DRMTexture* texture;
	TextureImpl* holder = new TextureImpl();
	Result result = ResultVal(m_data->groupMesh->GetGroupTexture(m_data->groupIndex, &texture));
	if (result) {
		// Seems to actually call the first virtual method of holder here
		// but that doesn't make any sense since it passes three arguments
		// to the method (self + string constant? + an offset?).

		// This line makes the start of the function match and is what I
		// would expect to see there but it clearly isn't what's actually
		// there.
		holder->SetImplementation(texture);
	}
	rpTexture = holder;
	return Success;
}
