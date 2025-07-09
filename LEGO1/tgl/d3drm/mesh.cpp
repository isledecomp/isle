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

// FUNCTION: BETA10 0x10170590
inline Result MeshSetColor(MeshImpl::MeshData* pMesh, float r, float g, float b, float a)
{
	if (a > 0) {
		D3DCOLOR color = D3DRMCreateColorRGBA(r, g, b, a);
		return ResultVal(pMesh->groupMesh->SetGroupColor(pMesh->groupIndex, color));
	}
	else {
		return ResultVal(pMesh->groupMesh->SetGroupColorRGB(pMesh->groupIndex, r, g, b));
	}
}

// FUNCTION: LEGO1 0x100a3ee0
// FUNCTION: BETA10 0x10170520
Result MeshImpl::SetColor(float r, float g, float b, float a)
{
	assert(m_data);

	return MeshSetColor(m_data, r, g, b, a);
}

// FUNCTION: BETA10 0x10171320
inline Result MeshSetTexture(MeshImpl::MeshData* pMesh, IDirect3DRMTexture* pD3DTexture)
{
	Result result = ResultVal(pMesh->groupMesh->SetGroupTexture(pMesh->groupIndex, pD3DTexture));
	return result;
}

// FUNCTION: BETA10 0x10171260
inline Result MeshImpl::SetTexture(const TextureImpl* pTexture)
{
	assert(m_data);
	assert(!pTexture || pTexture->ImplementationData());

	IDirect3DRMTexture* pD3DTexture = pTexture ? pTexture->ImplementationData() : NULL;
	return MeshSetTexture(m_data, pD3DTexture);
}

// FUNCTION: LEGO1 0x100a3f50
// FUNCTION: BETA10 0x10170630
Result MeshImpl::SetTexture(const Texture* pTexture)
{
	assert(m_data);

	return SetTexture(static_cast<const TextureImpl*>(pTexture));
}

// FUNCTION: LEGO1 0x100a3f80
// FUNCTION: BETA10 0x10170690
Result MeshImpl::SetTextureMappingMode(TextureMappingMode mode)
{
	assert(m_data);

	return MeshSetTextureMappingMode(m_data, mode);
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

inline Result MeshShallowClone(MeshImpl::MeshData* pSource, MeshImpl::MeshData*& rpTarget, IDirect3DRMMesh* pMesh)
{
	Result result = Error;
	rpTarget = new MeshImpl::MeshData();

	if (rpTarget) {
		rpTarget->groupMesh = pMesh;
		rpTarget->groupIndex = pSource->groupIndex;
		result = Success;
	}

	return result;
}

inline Mesh* MeshImpl::ShallowClone(const MeshBuilderImpl& rMesh)
{
	assert(m_data);
	assert(rMesh.ImplementationData());

	MeshImpl* clone = new MeshImpl();
	assert(!clone->ImplementationData());

	if (!MeshShallowClone(m_data, clone->ImplementationData(), rMesh.ImplementationData())) {
		delete clone;
		clone = NULL;
	}

	return clone;
}

// FUNCTION: LEGO1 0x100a4240
Mesh* MeshImpl::ShallowClone(MeshBuilder* pMeshBuilder)
{
	assert(m_data);
	assert(pMeshBuilder);

	return ShallowClone(*static_cast<MeshBuilderImpl*>(pMeshBuilder));
}

// FUNCTION: BETA10 0x10171ac0
inline Result MeshGetTexture(MeshImpl::MeshData* pMesh, IDirect3DRMTexture** pD3DTexture)
{
	return ResultVal(pMesh->groupMesh->GetGroupTexture(pMesh->groupIndex, pD3DTexture));
}

// FUNCTION: BETA10 0x10171980
inline Result MeshImpl::GetTexture(TextureImpl** ppTexture)
{
	assert(m_data);
	assert(ppTexture);

	TextureImpl* pTextureImpl = new TextureImpl();
	assert(pTextureImpl);

	// TODO: This helps retail match, but it adds to the stack
	IDirect3DRMTexture* tex;
	Result result = MeshGetTexture(m_data, &tex);

#ifndef BETA10
	if (Succeeded(result)) {
		result =
			ResultVal(tex->QueryInterface(IID_IDirect3DRMTexture2, (LPVOID*) (&pTextureImpl->ImplementationData())));
	}
#endif

	*ppTexture = pTextureImpl;
	return result;
}

// FUNCTION: LEGO1 0x100a4330
// FUNCTION: BETA10 0x10170820
Result MeshImpl::GetTexture(Texture*& rpTexture)
{
	assert(m_data);

	return GetTexture(reinterpret_cast<TextureImpl**>(&rpTexture));
}
