#include "impl.h"

#include <assert.h>

using namespace TglImpl;

DECOMP_SIZE_ASSERT(MeshBuilder, 0x04);
DECOMP_SIZE_ASSERT(MeshBuilderImpl, 0x08);

// FUNCTION: LEGO1 0x100a3830
// FUNCTION: BETA10 0x1016c9f0
void* MeshBuilderImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a3840
// FUNCTION: BETA10 0x1016ca40
Mesh* MeshBuilderImpl::CreateMesh(
	unsigned long faceCount,
	unsigned long vertexCount,
	float (*pPositions)[3],
	float (*pNormals)[3],
	float (*pTextureCoordinates)[2],
	unsigned long (*pFaceIndices)[3],
	unsigned long (*pTextureIndices)[3],
	ShadingModel shadingModel
)
{
	assert(m_data);

	MeshImpl* pMeshImpl = new MeshImpl;
	if (CreateMeshImpl(
			pMeshImpl,
			faceCount,
			vertexCount,
			pPositions,
			pNormals,
			pTextureCoordinates,
			pFaceIndices,
			pTextureIndices,
			shadingModel
		) == Error) {
		delete pMeshImpl;
		pMeshImpl = NULL;
	}

	return pMeshImpl;
}

// FUNCTION: BETA10 0x1016fef0
inline Result CreateMesh(
	IDirect3DRMMesh* pD3DRM,
	unsigned long p_numFaces,
	unsigned long p_numVertices,
	float(*p_positions),
	float(*p_normals),
	float(*p_textureCoordinates),
	unsigned long (*p_faceIndices)[3],
	unsigned long (*p_textureIndices)[3],
	ShadingModel shadingModel,
	MeshImpl::MeshDataType& rpMesh
)
{
	unsigned short* faceIndices = (unsigned short*) p_faceIndices;
	D3DRMGROUPINDEX groupIndex = 0;
	int faceCount = p_numFaces * 3;
	int count = 0;

	unsigned int* fData = new unsigned int[faceCount];

	D3DRMVERTEX* vertices = new D3DRMVERTEX[p_numVertices];
	memset(vertices, 0, sizeof(*vertices) * p_numVertices);

	rpMesh = new MeshImpl::MeshData;
	rpMesh->groupMesh = pD3DRM;

	for (int i = 0; i < faceCount; i++) {
		if (((faceIndices[2 * i + 1]) >> 0x0f) & 0x01) {
			unsigned long j = 3 * faceIndices[2 * i];
			vertices[count].position.x = p_positions[j];
			vertices[count].position.y = p_positions[j + 1];
			vertices[count].position.z = p_positions[j + 2];

			int k = 3 * (faceIndices[2 * i + 1] & MAXSHORT);
			vertices[count].normal.x = p_normals[k];
			vertices[count].normal.y = p_normals[k + 1];
			vertices[count].normal.z = p_normals[k + 2];

			if (p_textureIndices != NULL && p_textureCoordinates != NULL) {
				int kk = 2 * ((unsigned long*) p_textureIndices)[i];
				vertices[count].tu = p_textureCoordinates[kk];
				vertices[count].tv = p_textureCoordinates[kk + 1];
			}

			fData[i] = count;
			count++;
		}
		else {
			fData[i] = faceIndices[2 * i];
		}
	}

	assert(count == (int) p_numVertices);

	Result result;
	result = ResultVal(pD3DRM->AddGroup(p_numVertices, p_numFaces, 3, fData, &groupIndex));

	if (Succeeded(result)) {
		rpMesh->groupIndex = groupIndex;
		result = ResultVal(pD3DRM->SetVertices(groupIndex, 0, p_numVertices, vertices));
	}

	if (!Succeeded(result)) {
		if (rpMesh) {
			delete rpMesh;
		}
		rpMesh = NULL;
	}
	else {
		result = MeshSetTextureMappingMode(rpMesh, PerspectiveCorrect);
		assert(Succeeded(result));
	}

	if (fData != NULL) {
		delete[] fData;
	}

	if (vertices != NULL) {
		delete[] vertices;
	}

	return result;
}

// FUNCTION: BETA10 0x1016fe40
inline Result MeshBuilderImpl::CreateMeshImpl(
	MeshImpl* pMeshImpl,
	unsigned long faceCount,
	unsigned long vertexCount,
	float (*pPositions)[3],
	float (*pNormals)[3],
	float (*pTextureCoordinates)[2],
	unsigned long (*pFaceIndices)[3],
	unsigned long (*pTextureIndices)[3],
	ShadingModel shadingModel
)
{
	assert(m_data);
	assert(!pMeshImpl->ImplementationData());

	return ::CreateMesh(
		m_data,
		faceCount,
		vertexCount,
		reinterpret_cast<float*>(pPositions),
		reinterpret_cast<float*>(pNormals),
		reinterpret_cast<float*>(pTextureCoordinates),
		pFaceIndices,
		pTextureIndices,
		shadingModel,
		pMeshImpl->ImplementationData()
	);
}

// FUNCTION: BETA10 0x1016e060
inline Result MeshBuilderGetBoundingBox(IDirect3DRMMesh* pMesh, float min[3], float max[3])
{
	D3DRMBOX box;
	Result result = ResultVal(pMesh->GetBox(&box));
	if (Succeeded(result)) {
		min[0] = box.min.x;
		min[1] = box.min.y;
		min[2] = box.min.z;
		max[0] = box.max.x;
		max[1] = box.max.y;
		max[2] = box.max.z;
	}
	return result;
}

// FUNCTION: LEGO1 0x100a3ae0
// FUNCTION: BETA10 0x1016ce00
Result MeshBuilderImpl::GetBoundingBox(float min[3], float max[3]) const
{
	assert(m_data);

	return MeshBuilderGetBoundingBox(m_data, min, max);
}

// FUNCTION: LEGO1 0x100a3b40
MeshBuilder* MeshBuilderImpl::Clone()
{
	MeshBuilderImpl* mesh = new MeshBuilderImpl();
	int ret = m_data->Clone(0, IID_IDirect3DRMMesh, (void**) &mesh->m_data);
	if (ret < 0) {
		delete mesh;
		mesh = NULL;
	}
	return mesh;
}
