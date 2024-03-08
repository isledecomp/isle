#include "impl.h"

using namespace TglImpl;

DECOMP_SIZE_ASSERT(Unk, 0x04);
DECOMP_SIZE_ASSERT(UnkImpl, 0x08);

// FUNCTION: LEGO1 0x100a3830
void* UnkImpl::ImplementationDataPtr()
{
	return reinterpret_cast<void*>(&m_data);
}

// FUNCTION: LEGO1 0x100a3840
Mesh* UnkImpl::CreateMesh(
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
	MeshImpl* mesh = new MeshImpl();
	if (CreateMeshImpl(
			mesh,
			faceCount,
			vertexCount,
			pPositions,
			pNormals,
			pTextureCoordinates,
			pFaceIndices,
			pTextureIndices,
			shadingModel
		) == Error) {
		delete mesh;
		mesh = NULL;
	}

	return mesh;
}

inline Result MeshSetTextureMappingMode(MeshImpl::MeshData* pMesh, TextureMappingMode mode)
{
	if (mode == PerspectiveCorrect) {
		return ResultVal(pMesh->groupMesh->SetGroupMapping(pMesh->groupIndex, D3DRMMAP_PERSPCORRECT));
	}
	else {
		return ResultVal(pMesh->groupMesh->SetGroupMapping(pMesh->groupIndex, 0));
	}
}

inline Result CreateMesh(
	IDirect3DRMMesh* pD3DRM,
	unsigned long faceCount,
	unsigned long vertexCount,
	float (*pPositions)[3],
	float (*pNormals)[3],
	float (*pTextureCoordinates)[2],
	unsigned long (*pFaceIndices)[3],
	unsigned long (*pTextureIndices)[3],
	ShadingModel shadingModel,
	MeshImpl::MeshDataType& rpMesh
)
{
	unsigned long* faceIndices = (unsigned long*) pFaceIndices;
	D3DRMGROUPINDEX groupIndex = 0;
	int count = faceCount * 3;
	int index = 0;

	unsigned int* fData = new unsigned int[count];

	D3DRMVERTEX* vertices = new D3DRMVERTEX[vertexCount];
	memset(vertices, 0, sizeof(*vertices) * vertexCount);

	rpMesh = new MeshImpl::MeshData;
	rpMesh->groupMesh = pD3DRM;

	for (int i = 0; i < count; i++) {
		if (*((unsigned char*) &faceIndices[i] + 3) & 0x80) {
			unsigned long j = *(unsigned short*) &faceIndices[i];
			vertices[index].position.x = pPositions[j][0];
			vertices[index].position.y = pPositions[j][1];
			vertices[index].position.z = pPositions[j][2];
			j = *((unsigned short*) &faceIndices[i] + 1) & MAXSHORT;
			vertices[index].normal.x = pNormals[j][0];
			vertices[index].normal.y = pNormals[j][1];
			vertices[index].normal.z = pNormals[j][2];

			if (pTextureIndices != NULL && pTextureCoordinates != NULL) {
				j = ((unsigned long*) pTextureIndices)[i];
				vertices[index].tu = pTextureCoordinates[j][0];
				vertices[index].tv = pTextureCoordinates[j][1];
			}

			fData[i] = index;
			index++;
		}
		else {
			fData[i] = *(unsigned short*) &faceIndices[i];
		}
	}

	Result result;
	result = ResultVal(pD3DRM->AddGroup(vertexCount, faceCount, 3, fData, &groupIndex));

	if (Succeeded(result)) {
		rpMesh->groupIndex = groupIndex;
		result = ResultVal(pD3DRM->SetVertices(groupIndex, 0, vertexCount, vertices));
	}

	if (!Succeeded(result)) {
		delete rpMesh->groupMesh;
		rpMesh->groupMesh = NULL;
	}
	else {
		result = MeshSetTextureMappingMode(rpMesh, PerspectiveCorrect);
	}

	if (fData != NULL) {
		delete[] fData;
	}

	if (vertices != NULL) {
		delete[] vertices;
	}

	if (!Succeeded(result)) {
		delete rpMesh;
	}

	return result;
}

inline Result UnkImpl::CreateMeshImpl(
	MeshImpl* mesh,
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
	return ::CreateMesh(
		m_data,
		faceCount,
		vertexCount,
		pPositions,
		pNormals,
		pTextureCoordinates,
		pFaceIndices,
		pTextureIndices,
		shadingModel,
		mesh->ImplementationData()
	);
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
