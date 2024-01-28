#include "impl.h"

using namespace TglImpl;

// FUNCTION: LEGO1 0x100a31d0
void* GroupImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a31e0
Result GroupImpl::SetTransformation(FloatMatrix4& matrix)
{
	D3DRMMATRIX4D helper;
	D3DRMMATRIX4D* d3dMatrix = Translate(matrix, helper);
	return ResultVal(m_data->AddTransform(D3DRMCOMBINE_REPLACE, *d3dMatrix));
}

// FUNCTION: LEGO1 0x100a3240
Result GroupImpl::SetColor(float r, float g, float b, float a)
{
	// The first instruction makes no sense here:
	// cmp dword ptr [esp + 0x10], 0
	// This compares a, which we know is a float because it immediately
	// gets passed into D3DRMCreateColorRGBA, but does the comparison
	// as though it's an int??
	if (*reinterpret_cast<int*>(&a) > 0) {
		D3DCOLOR color = D3DRMCreateColorRGBA(r, g, b, a);
		return ResultVal(m_data->SetColor(color));
	}
	else {
		return ResultVal(m_data->SetColorRGB(r, a, b));
	}
}

// FUNCTION: LEGO1 0x100a32b0
Result GroupImpl::SetTexture(const Texture* pTexture)
{
	IDirect3DRMTexture* pD3DTexture = pTexture ? static_cast<const TextureImpl*>(pTexture)->ImplementationData() : NULL;
	return ResultVal(m_data->SetTexture(pD3DTexture));
}

// FUNCTION: LEGO1 0x100a32e0
Result GroupImpl::GetTexture(Texture*& pTexture)
{
	IDirect3DRMTexture* pD3DTexture;
	TextureImpl* holder = new TextureImpl();
	Result result = ResultVal(m_data->GetTexture(&pD3DTexture));
	if (result) {
		// Seems to actually call the first virtual method of holder here
		// but that doesn't make any sense since it passes three arguments
		// to the method (self + string constant? + an offset?).

		// This line makes the start of the function match and is what I
		// would expect to see there but it clearly isn't what's actually
		// there.
		holder->SetImplementation(pD3DTexture);
	}
	pTexture = holder;
	return Success;
}

// FUNCTION: LEGO1 0x100a33c0
Result GroupImpl::SetMaterialMode(MaterialMode mode)
{
	D3DRMMATERIALMODE d3dMode;
	switch (mode) {
	case FromParent:
		d3dMode = D3DRMMATERIAL_FROMPARENT;
		break;
	case FromFrame:
		d3dMode = D3DRMMATERIAL_FROMFRAME;
		break;
	case FromMesh:
		d3dMode = D3DRMMATERIAL_FROMMESH;
		break;
	}
	return ResultVal(m_data->SetMaterialMode(d3dMode));
}

// FUNCTION: LEGO1 0x100a3410
Result GroupImpl::Add(const Mesh* pMesh)
{
	const MeshImpl* pMeshImpl = static_cast<const MeshImpl*>(pMesh);
	return ResultVal(m_data->AddVisual(pMeshImpl->ImplementationData()->groupMesh));
}

// FUNCTION: LEGO1 0x100a3430
Result GroupImpl::Add(const Group* pGroup)
{
	const GroupImpl* pGroupImpl = static_cast<const GroupImpl*>(pGroup);
	return ResultVal(m_data->AddVisual(pGroupImpl->m_data));
}

// FUNCTION: LEGO1 0x100a3450
Result GroupImpl::Remove(const Group* pGroup)
{
	const GroupImpl* pGroupImpl = static_cast<const GroupImpl*>(pGroup);
	return ResultVal(m_data->DeleteVisual(pGroupImpl->m_data));
}

// FUNCTION: LEGO1 0x100a3480
Result GroupImpl::Remove(const Mesh* pMesh)
{
	const MeshImpl* pMeshImpl = static_cast<const MeshImpl*>(pMesh);
	return ResultVal(m_data->DeleteVisual(pMeshImpl->ImplementationData()->groupMesh));
}

// STUB: LEGO1 0x100a34b0
Result GroupImpl::RemoveAll()
{
	return Error;
}

// STUB: LEGO1 0x100a3540
Result GroupImpl::Unknown()
{
	return Error;
}
