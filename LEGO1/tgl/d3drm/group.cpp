#include "impl.h"

using namespace TglImpl;

// Inlined only
GroupImpl::~GroupImpl()
{
	if (m_data) {
		free(m_data);
		m_data = NULL;
	}
}

// OFFSET: LEGO1 0x100a31d0
void* GroupImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// OFFSET: LEGO1 0x100a31e0
Result GroupImpl::SetTransformation(const FloatMatrix4& p_matrix)
{
	D3DRMMATRIX4D helper;
	D3DRMMATRIX4D* matrix = Translate(p_matrix, helper);
	return ResultVal(m_data->AddTransform(D3DRMCOMBINE_REPLACE, *matrix));
}

// OFFSET: LEGO1 0x100a3240
Result GroupImpl::SetColor(float p_r, float p_g, float p_b, float p_a)
{
	// The first instruction makes no sense here:
	// cmp dword ptr [esp + 0x10], 0
	// This compares a, which we know is a float because it immediately
	// gets passed into D3DRMCreateColorRGBA, but does the comparison
	// as though it's an int??
	if (*reinterpret_cast<int*>(&p_a) > 0) {
		D3DCOLOR color = D3DRMCreateColorRGBA(p_r, p_g, p_b, p_a);
		return ResultVal(m_data->SetColor(color));
	}
	else {
		return ResultVal(m_data->SetColorRGB(p_r, p_a, p_b));
	}
}

// OFFSET: LEGO1 0x100a32b0
Result GroupImpl::SetTexture(const Texture* p_texture)
{
	IDirect3DRMTexture* texture = p_texture ? static_cast<const TextureImpl*>(p_texture)->ImplementationData() : NULL;
	return ResultVal(m_data->SetTexture(texture));
}

// OFFSET: LEGO1 0x100a32e0
Result GroupImpl::GetTexture(Texture*& p_texture)
{
	IDirect3DRMTexture* texture;
	TextureImpl* holder = new TextureImpl();
	Result result = ResultVal(m_data->GetTexture(&texture));
	if (result) {
		// Seems to actually call the first virtual method of holder here
		// but that doesn't make any sense since it passes three arguments
		// to the method (self + string constant? + an offset?).

		// This line makes the start of the function match and is what I
		// would expect to see there but it clearly isn't what's actually
		// there.
		holder->SetImplementation(texture);
	}
	p_texture = holder;
	return Success;
}

// OFFSET: LEGO1 0x100a33c0
Result GroupImpl::SetMaterialMode(MaterialMode p_mode)
{
	D3DRMMATERIALMODE mode;
	switch (p_mode)
	{
	case FromParent:
		mode = D3DRMMATERIAL_FROMPARENT;
		break;
	case FromFrame:
		mode = D3DRMMATERIAL_FROMFRAME;
		break;
	case FromMesh:
		mode = D3DRMMATERIAL_FROMMESH;
		break;
	}
	return ResultVal(m_data->SetMaterialMode(mode));
}

// OFFSET: LEGO1 0x100a3430
Result GroupImpl::Add(const Group* p_group)
{
	const GroupImpl* group = static_cast<const GroupImpl*>(p_group);
	return ResultVal(m_data->AddVisual(group->m_data));
}

// OFFSET: LEGO1 0x100a3410
Result GroupImpl::Add(const Mesh* p_mesh)
{
	const MeshImpl* mesh = static_cast<const MeshImpl*>(p_mesh);
	return ResultVal(m_data->AddVisual(mesh->ImplementationData()->groupMesh));
}

// OFFSET: LEGO1 0x100a3450
Result GroupImpl::Remove(const Group* p_group)
{
	const GroupImpl* group = static_cast<const GroupImpl*>(p_group);
	return ResultVal(m_data->DeleteVisual(group->m_data));
}

// OFFSET: LEGO1 0x100a3480
Result GroupImpl::Remove(const Mesh* p_mesh)
{
	const MeshImpl* mesh = static_cast<const MeshImpl*>(p_mesh);
	return ResultVal(m_data->DeleteVisual(mesh->ImplementationData()->groupMesh));
}

// OFFSET: LEGO1 0x100a34b0 STUB
Result GroupImpl::RemoveAll()
{
	return Error;
}

// OFFSET: LEGO1 0x100a34c0 STUB
Result GroupImpl::Unknown()
{
	return Error;
}
