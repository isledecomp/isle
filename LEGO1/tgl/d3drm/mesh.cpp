#include "impl.h"

using namespace TglImpl;

DECOMP_SIZE_ASSERT(D3DRMVERTEX, 0x24);

DECOMP_SIZE_ASSERT(Mesh, 0x04);
DECOMP_SIZE_ASSERT(MeshImpl, 0x08);

// FUNCTION: LEGO1 0x100a3ed0
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

// FUNCTION: LEGO1 0x100a3fc0
Result MeshImpl::SetShadingModel(ShadingModel model)
{
	D3DRMRENDERQUALITY mode;
	switch (model) {
	case Wireframe:
		mode = D3DRMRENDER_WIREFRAME;
		break;
	case UnlitFlat:
		mode = D3DRMRENDER_UNLITFLAT;
		break;
	case Flat:
		mode = D3DRMRENDER_FLAT;
		break;
	case Gouraud:
		mode = D3DRMRENDER_GOURAUD;
		break;
	case Phong:
		mode = D3DRMRENDER_PHONG;
		break;
	}
	return ResultVal(m_data->groupMesh->SetGroupQuality(m_data->groupIndex, mode));
}

// FUNCTION: LEGO1 0x100a4030
Mesh* MeshImpl::DeepClone(MeshBuilder* pMeshBuilder)
{
	// Create group
	MeshImpl* newMesh = new MeshImpl();
	MeshData* data = new MeshData();
	newMesh->m_data = data;

	// Query information from old group
	DWORD dataSize;
	unsigned int vcount, fcount, vperface;
	m_data->groupMesh->GetGroup(m_data->groupIndex, &vcount, &fcount, &vperface, &dataSize, NULL);
	unsigned int* faceBuffer = new unsigned int[dataSize];
	m_data->groupMesh->GetGroup(m_data->groupIndex, &vcount, &fcount, &vperface, &dataSize, faceBuffer);
	// We expect vertex to be sized 0x24, checked at start of file.
	D3DRMVERTEX* vertexBuffer = new D3DRMVERTEX[vcount];
	m_data->groupMesh->GetVertices(m_data->groupIndex, 0, vcount, vertexBuffer);
	LPDIRECT3DRMTEXTURE textureRef;
	m_data->groupMesh->GetGroupTexture(m_data->groupIndex, &textureRef);
	D3DRMMAPPING mapping = m_data->groupMesh->GetGroupMapping(m_data->groupIndex);
	D3DRMRENDERQUALITY quality = m_data->groupMesh->GetGroupQuality(m_data->groupIndex);
	D3DCOLOR color = m_data->groupMesh->GetGroupColor(m_data->groupIndex);

	// Push information to new group
	MeshBuilderImpl* target = static_cast<MeshBuilderImpl*>(pMeshBuilder);
	D3DRMGROUPINDEX index;
	target->ImplementationData()->AddGroup(vcount, fcount, vperface, faceBuffer, &index);
	newMesh->m_data->groupIndex = index;
	target->ImplementationData()->SetVertices(index, 0, vcount, vertexBuffer);
	target->ImplementationData()->SetGroupTexture(index, textureRef);
	target->ImplementationData()->SetGroupMapping(index, mapping);
	target->ImplementationData()->SetGroupQuality(index, quality);
	Result result = ResultVal(target->ImplementationData()->SetGroupColor(index, color));

	// Cleanup
	delete[] faceBuffer;
	delete[] vertexBuffer;
	if (result == Error) {
		delete newMesh;
		newMesh = NULL;
	}

	return newMesh;
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
