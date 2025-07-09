#include "impl.h"

#include <assert.h>

using namespace TglImpl;

// FUNCTION: LEGO1 0x100a31d0
// FUNCTION: BETA10 0x1016a480
void* GroupImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: BETA10 0x1016c340
inline Result GroupSetTransformation(IDirect3DRMFrame2* pGroup, FloatMatrix4& matrix)
{
	D3DRMMATRIX4D helper;
	D3DRMMATRIX4D* d3dMatrix = Translate(matrix, helper);
	return ResultVal(pGroup->AddTransform(D3DRMCOMBINE_REPLACE, *d3dMatrix));
}

// FUNCTION: LEGO1 0x100a31e0
// FUNCTION: BETA10 0x1016a4d0
Result GroupImpl::SetTransformation(FloatMatrix4& matrix)
{
	assert(m_data);

	return GroupSetTransformation(m_data, matrix);
}

// FUNCTION: BETA10 0x1016c400
inline Result GroupSetColor(IDirect3DRMFrame2* pGroup, float r, float g, float b, float a)
{
	if (a > 0) {
		D3DCOLOR color = D3DRMCreateColorRGBA(r, g, b, a);
		return ResultVal(pGroup->SetColor(color));
	}
	else {
		return ResultVal(pGroup->SetColorRGB(r, g, b));
	}
}

// FUNCTION: LEGO1 0x100a3240
// FUNCTION: BETA10 0x1016a530
Result GroupImpl::SetColor(float r, float g, float b, float a)
{
	assert(m_data);

	return GroupSetColor(m_data, r, g, b, a);
}

// FUNCTION: BETA10 0x1016c5a0
inline Result GroupSetTexture(IDirect3DRMFrame2* pGroup, IDirect3DRMTexture* pD3DTexture)
{
	return ResultVal(pGroup->SetTexture(pD3DTexture));
}

// FUNCTION: BETA10 0x1016bcc0
inline Result GroupImpl::SetTexture(const TextureImpl* pTexture)
{
	assert(m_data);
	assert(!pTexture || pTexture->ImplementationData());

	IDirect3DRMTexture* pD3DTexture = pTexture ? pTexture->ImplementationData() : NULL;
	return GroupSetTexture(m_data, pD3DTexture);
}

// FUNCTION: LEGO1 0x100a32b0
// FUNCTION: BETA10 0x1016a5a0
Result GroupImpl::SetTexture(const Texture* pTexture)
{
	assert(m_data);

	return SetTexture(static_cast<const TextureImpl*>(pTexture));
}

// FUNCTION: BETA10 0x1016c640
inline Result GroupGetTexture(IDirect3DRMFrame2* pGroup, IDirect3DRMTexture** pD3DTexture)
{
	return ResultVal(pGroup->GetTexture(pD3DTexture));
}

// FUNCTION: BETA10 0x1016beb0
inline Result GroupImpl::GetTexture(TextureImpl** ppTexture)
{
	assert(m_data);
	assert(ppTexture);

	TextureImpl* pTextureImpl = new TextureImpl();
	assert(pTextureImpl);

	// TODO: This helps retail match, but it adds to the stack
	IDirect3DRMTexture* tex;
	Result result = GroupGetTexture(m_data, &tex);

#ifndef BETA10
	if (Succeeded(result)) {
		result =
			ResultVal(tex->QueryInterface(IID_IDirect3DRMTexture2, (LPVOID*) (&pTextureImpl->ImplementationData())));
	}
#endif

	*ppTexture = pTextureImpl;
	return result;
}

// FUNCTION: LEGO1 0x100a32e0
// FUNCTION: BETA10 0x1016a600
Result GroupImpl::GetTexture(Texture*& pTexture)
{
	assert(m_data);

	return GetTexture(reinterpret_cast<TextureImpl**>(&pTexture));
}

// FUNCTION: BETA10 0x1016c500
inline Result GroupSetMaterialMode(IDirect3DRMFrame2* pGroup, MaterialMode mode)
{
	D3DRMMATERIALMODE d3dMode = Translate(mode);
	return ResultVal(pGroup->SetMaterialMode(d3dMode));
}

// FUNCTION: LEGO1 0x100a33c0
// FUNCTION: BETA10 0x1016a660
Result GroupImpl::SetMaterialMode(MaterialMode mode)
{
	assert(m_data);

	return GroupSetMaterialMode(m_data, mode);
}

// FUNCTION: BETA10 0x1016c670
inline Result GroupAddGroup(IDirect3DRMFrame2* pGroup, const IDirect3DRMFrame* pChildGroup)
{
	return ResultVal(pGroup->AddVisual(const_cast<IDirect3DRMFrame*>(pChildGroup)));
}

// FUNCTION: BETA10 0x1016c090
inline Result GroupImpl::Add(const GroupImpl& rGroup)
{
	assert(m_data);
	assert(rGroup.ImplementationData());

	return GroupAddGroup(m_data, rGroup.ImplementationData());
}

// FUNCTION: LEGO1 0x100a3410
// FUNCTION: BETA10 0x1016a6c0
Result GroupImpl::Add(const Group* pGroup)
{
	assert(m_data);
	assert(pGroup);

	return Add(*static_cast<const GroupImpl*>(pGroup));
}

// FUNCTION: BETA10 0x1016c700
inline Result GroupAddMeshBuilder(IDirect3DRMFrame2* pGroup, const IDirect3DRMMesh* pMesh)
{
	return ResultVal(pGroup->AddVisual(const_cast<IDirect3DRMMesh*>(pMesh)));
}

// FUNCTION: BETA10 0x1016bff0
inline Result GroupImpl::Add(const MeshBuilderImpl& rMesh)
{
	assert(m_data);
	assert(rMesh.ImplementationData());

	return GroupAddMeshBuilder(m_data, rMesh.ImplementationData());
}

// FUNCTION: LEGO1 0x100a3430
// FUNCTION: BETA10 0x1016a740
Result GroupImpl::Add(const MeshBuilder* pMeshBuilder)
{
	assert(m_data);
	assert(pMeshBuilder);

	return Add(*static_cast<const MeshBuilderImpl*>(pMeshBuilder));
}

// FUNCTION: BETA10 0x1016c7b0
inline Result GroupRemoveMeshBuilder(IDirect3DRMFrame2* pGroup, const IDirect3DRMMesh* pMesh)
{
	return ResultVal(pGroup->DeleteVisual(const_cast<IDirect3DRMMesh*>(pMesh)));
}

// FUNCTION: BETA10 0x1016c130
inline Result GroupImpl::Remove(const MeshBuilderImpl& rMesh)
{
	assert(m_data);
	assert(rMesh.ImplementationData());

	return GroupRemoveMeshBuilder(m_data, rMesh.ImplementationData());
}

// FUNCTION: LEGO1 0x100a3450
// FUNCTION: BETA10 0x1016a7c0
Result GroupImpl::Remove(const MeshBuilder* pMeshBuilder)
{
	assert(m_data);
	assert(pMeshBuilder);

	return Remove(*static_cast<const MeshBuilderImpl*>(pMeshBuilder));
}

// FUNCTION: BETA10 0x1016c730
inline Result GroupRemoveGroup(IDirect3DRMFrame2* pGroup, const IDirect3DRMFrame* pChildGroup)
{
	return ResultVal(pGroup->DeleteVisual(const_cast<IDirect3DRMFrame*>(pChildGroup)));
}

// FUNCTION: BETA10 0x1016c1d0
inline Result GroupImpl::Remove(const GroupImpl& rGroup)
{
	assert(m_data);
	assert(rGroup.ImplementationData());

	return GroupRemoveGroup(m_data, rGroup.ImplementationData());
}

// FUNCTION: LEGO1 0x100a3480
// FUNCTION: BETA10 0x1016a840
Result GroupImpl::Remove(const Group* pGroup)
{
	assert(m_data);
	assert(pGroup);

	return Remove(*static_cast<const GroupImpl*>(pGroup));
}

// FUNCTION: BETA10 0x1016c850
inline Result GroupRemoveAll(IDirect3DRMFrame2* pFrame)
{
	IDirect3DRMVisualArray* visuals;
	int refCount;

	Result result = ResultVal(pFrame->GetVisuals(&visuals));
	assert(Succeeded(result));

	if (Succeeded(result)) {
		for (int i = 0; i < (int) visuals->GetSize(); i++) {
			IDirect3DRMVisual* visual;

			result = ResultVal(visuals->GetElement(i, &visual));
			assert(Succeeded(result));

			result = ResultVal(pFrame->DeleteVisual(visual));
			assert(Succeeded(result));

			refCount = visual->Release();
		}

		refCount = visuals->Release();
		assert(refCount == 0);
	}

	return result;
}

// FUNCTION: LEGO1 0x100a34b0
// FUNCTION: BETA10 0x1016a8c0
Result GroupImpl::RemoveAll()
{
	assert(m_data);

	return GroupRemoveAll(m_data);
}

// FUNCTION: BETA10 0x1016cb70
inline Result GroupBounds(IDirect3DRMFrame2* pFrame, D3DVECTOR* p_min, D3DVECTOR* p_max)
{
	D3DRMBOX size;
	int refCount;

	size.min.x = size.min.y = size.min.z = 88888.f;
	size.max.x = size.max.y = size.max.z = -88888.f;

	IDirect3DRMVisualArray* visuals;
	Result result = ResultVal(pFrame->GetVisuals(&visuals));
	assert(Succeeded(result));

	if (Succeeded(result)) {
		for (int i = 0; i < (int) visuals->GetSize(); i++) {
			IDirect3DRMVisual* visual;
			result = ResultVal(visuals->GetElement(i, &visual));
			assert(Succeeded(result));

			/*
			 * BUG: should be:
			 *  visual->QueryInterface(IID_IDirect3DRMMesh, (void**)&mesh));
			 */
			IDirect3DRMMesh* mesh;
			result = ResultVal(visual->QueryInterface(IID_IDirect3DRMMeshBuilder, (void**) &mesh));

			if (Succeeded(result)) {
				D3DRMBOX box;
				result = ResultVal(mesh->GetBox(&box));
				assert(Succeeded(result));

				if (box.min.x < size.min.x) {
					size.min.x = box.min.x;
				}
				if (box.min.y < size.min.y) {
					size.min.y = box.min.y;
				}
				if (box.min.z < size.min.z) {
					size.min.z = box.min.z;
				}
				if (size.max.x < box.max.x) {
					size.max.x = box.max.x;
				}
				if (size.max.y < box.max.y) {
					size.max.y = box.max.y;
				}
				if (size.max.z < box.max.z) {
					size.max.z = box.max.z;
				}

				mesh->Release();
			}

			refCount = visual->Release();
		}

		refCount = visuals->Release();
	}

	p_min->x = size.min.x;
	p_min->y = size.min.y;
	p_min->z = size.min.z;
	p_max->x = size.max.x;
	p_max->y = size.max.y;
	p_max->z = size.max.z;
	return result;
}

// FUNCTION: LEGO1 0x100a3540
// FUNCTION: BETA10 0x1016a920
Result GroupImpl::Bounds(D3DVECTOR* p_min, D3DVECTOR* p_max)
{
	assert(m_data);

	return GroupBounds(m_data, p_min, p_max);
}
