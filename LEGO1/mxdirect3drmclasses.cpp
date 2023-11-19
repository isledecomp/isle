#include "mxdirect3drmclasses.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(IMxDirect3DRMFrame, 0x4);
DECOMP_SIZE_ASSERT(MxDirect3DRMFrame, 0x8);

// OFFSET: LEGO1 0x100a36f0
IUnknown** MxDirect3DRMFrame::GetHandle()
{
	return (IUnknown**) &m_pDirect3DRMFrame;
}

// Not 100% confident on this function signature or behavior.
// Known info: Calls GetPosition, then AddTransform, then GetPosition again.
// OFFSET: LEGO1 0x100a3700
int MxDirect3DRMFrame::AddTransform(D3DRMMATRIX4D* p_matrix, D3DVECTOR* p_oldPosition)
{
	D3DRMMATRIX4D newMatrix;
	D3DVECTOR anotherPosition;
	memcpy(&newMatrix, p_matrix, sizeof(D3DRMMATRIX4D));
	m_pDirect3DRMFrame->GetPosition(NULL, p_oldPosition);
	HRESULT result = m_pDirect3DRMFrame->AddTransform(D3DRMCOMBINE_REPLACE, newMatrix);
	m_pDirect3DRMFrame->GetPosition(NULL, &anotherPosition);
	return SUCCEEDED(result);
}

DECOMP_SIZE_ASSERT(IMxDirect3DRMLight, 0x4);
DECOMP_SIZE_ASSERT(MxDirect3DRMLight, 0x8);

// OFFSET: LEGO1 0x100a3770
IUnknown** MxDirect3DRMLight::GetHandle()
{
	return (IUnknown**) &m_pFrameWithLight;
}

// OFFSET: LEGO1 0x100a3780 STUB
int MxDirect3DRMLight::AddTransform(D3DRMMATRIX4D* p_matrix)
{
	return 0;
}

// OFFSET: LEGO1 0x100a37e0
int MxDirect3DRMLight::SetColorRGB(float p_r, float p_g, float p_b)
{
	IDirect3DRMLightArray* lightArray;
	IDirect3DRMLight* light;
	m_pFrameWithLight->GetLights(&lightArray);
	lightArray->GetElement(0, &light);
	return SUCCEEDED(light->SetColorRGB(p_r, p_g, p_b));
}

DECOMP_SIZE_ASSERT(IMxDirect3DRMMesh, 0x4);
DECOMP_SIZE_ASSERT(MxDirect3DRMMesh, 0x8);

// OFFSET: LEGO1 0x100a3830
IUnknown** MxDirect3DRMMesh::GetHandle()
{
	return (IUnknown**) &m_pDirect3DRMMesh;
}

// OFFSET: LEGO1 0x100a3840 STUB
int MxDirect3DRMMesh::SetMeshData(
	int p_faceCount,
	int p_vertexCount,
	void* p_positions,
	void* p_normals,
	void* p_uvs,
	int p_unk1,
	int* p_unk2
)
{
	return 0;
}

// OFFSET: LEGO1 0x100a3ae0
int MxDirect3DRMMesh::GetBox(float* p_minVec3, float* p_maxVec3)
{
	D3DRMBOX box;
	int ret = SUCCEEDED(m_pDirect3DRMMesh->GetBox(&box));
	if (ret == TRUE) {
		p_minVec3[0] = box.min.x;
		p_minVec3[1] = box.min.y;
		p_minVec3[2] = box.min.z;
		p_maxVec3[0] = box.max.x;
		p_maxVec3[1] = box.max.y;
		p_maxVec3[2] = box.max.z;
	}
	return ret;
}

// OFFSET: LEGO1 0x100a3b40
IMxDirect3DRMMesh* MxDirect3DRMMesh::Clone()
{
	MxDirect3DRMMesh* mesh = new MxDirect3DRMMesh();
	int ret = m_pDirect3DRMMesh->Clone(0, IID_IDirect3DRMMeshBuilder, (void**) &mesh->m_pDirect3DRMMesh);
	if (ret < 0) {
		delete mesh;
		mesh = NULL;
	}
	return mesh;
}
