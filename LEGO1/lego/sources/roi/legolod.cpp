
#include "legolod.h"

#include "geom/legomesh.h"
#include "legoroi.h"
#include "misc/legocontainer.h"
#include "misc/legostorage.h"
#include "tgl/d3drm/impl.h"

DECOMP_SIZE_ASSERT(LODObject, 0x04)
DECOMP_SIZE_ASSERT(ViewLOD, 0x0c)
DECOMP_SIZE_ASSERT(LegoLOD, 0x20)
DECOMP_SIZE_ASSERT(LegoLOD::Mesh, 0x08)

// GLOBAL: LEGO1 0x101013d4
LPDIRECT3DRMMATERIAL g_unk0x101013d4 = NULL;

// GLOBAL: LEGO1 0x101013dc
const char* g_unk0x101013dc = "inh";

inline IDirect3DRM2* GetD3DRM(Tgl::Renderer* pRenderer);
inline BOOL GetMeshData(IDirect3DRMMesh*& mesh, D3DRMGROUPINDEX& index, Tgl::Mesh* pMesh);

// FUNCTION: LEGO1 0x100aa380
LegoLOD::LegoLOD(Tgl::Renderer* p_renderer) : ViewLOD(p_renderer)
{
	if (g_unk0x101013d4 == NULL) {
		GetD3DRM(p_renderer)->CreateMaterial(10.0, &g_unk0x101013d4);
	}

	m_melems = NULL;
	m_numMeshes = 0;
	m_numVertices = 0;
	m_numPolys = 0;
	m_unk0x1c = 0;
}

// FUNCTION: LEGO1 0x100aa450
LegoLOD::~LegoLOD()
{
	if (m_numMeshes && m_melems != NULL) {
		for (LegoU32 i = 0; i < m_numMeshes; i++) {
			if (m_melems[i].m_tglMesh != NULL) {
				delete m_melems[i].m_tglMesh;
				m_melems[i].m_tglMesh = NULL;
			}
		}
	}

	if (m_melems) {
		delete[] m_melems;
	}
}

// FUNCTION: LEGO1 0x100aa510
LegoResult LegoLOD::Read(Tgl::Renderer* p_renderer, LegoTextureContainer* p_textureContainer, LegoStorage* p_storage)
{
	float(*normals)[3] = NULL;
	float(*vertices)[3] = NULL;
	float(*textureVertices)[2] = NULL;
	LegoS32 numVerts = 0;
	LegoS32 numNormals = 0;
	LegoS32 numTextureVertices = 0;
	LegoMesh* mesh = NULL;
	LegoU32(*polyIndices)[3] = NULL;
	LegoU32(*textureIndices)[3] = NULL;
	LegoTextureInfo* textureInfo = NULL;

	LegoU32 i, meshUnd1, meshUnd2, tempNumVertsAndNormals;
	unsigned char paletteEntries[256];

	if (p_storage->Read(&m_unk0x08, sizeof(m_unk0x08)) != SUCCESS) {
		goto done;
	}

	if (GetUnknown0x08Test4()) {
		return SUCCESS;
	}

	m_meshBuilder = p_renderer->CreateMeshBuilder();

	if (p_storage->Read(&m_numMeshes, sizeof(m_numMeshes)) != SUCCESS) {
		goto done;
	}

	if (m_numMeshes == 0) {
		ClearFlag(c_bit4);
		return SUCCESS;
	}

	SetFlag(c_bit4);

	m_melems = new Mesh[m_numMeshes];
	memset(m_melems, 0, sizeof(*m_melems) * m_numMeshes);

	meshUnd1 = m_numMeshes - 1;
	meshUnd2 = 0;

	if (p_storage->Read(&tempNumVertsAndNormals, sizeof(tempNumVertsAndNormals)) != SUCCESS) {
		goto done;
	}

	numVerts = *((LegoU16*) &tempNumVertsAndNormals) & MAXSHORT;
	numNormals = (*((LegoU16*) &tempNumVertsAndNormals + 1) >> 1) & MAXSHORT;

	if (p_storage->Read(&numTextureVertices, sizeof(numTextureVertices)) != SUCCESS) {
		goto done;
	}

	if (numVerts > 0) {
		vertices = new float[numVerts][_countof(*vertices)];
		if (p_storage->Read(vertices, numVerts * sizeof(*vertices)) != SUCCESS) {
			goto done;
		}
	}

	if (numNormals > 0) {
		normals = new float[numNormals][_countof(*normals)];
		if (p_storage->Read(normals, numNormals * sizeof(*normals)) != SUCCESS) {
			goto done;
		}
	}

	if (numTextureVertices > 0) {
		textureVertices = new float[numTextureVertices][_countof(*textureVertices)];
		if (p_storage->Read(textureVertices, numTextureVertices * sizeof(*textureVertices)) != SUCCESS) {
			goto done;
		}
	}

	for (i = 0; i < m_numMeshes; i++) {
		LegoU32 numPolys, numVertices, numTextureIndices, meshIndex;
		const LegoChar *textureName, *materialName;
		Tgl::ShadingModel shadingModel;

		if (p_storage->Read(&numPolys, 2) != SUCCESS) {
			goto done;
		}

		m_numPolys += numPolys & MAXWORD;

		if (p_storage->Read(&numVertices, 2) != SUCCESS) {
			goto done;
		}

		polyIndices = new LegoU32[numPolys & MAXWORD][_countof(*polyIndices)];
		if (p_storage->Read(polyIndices, (numPolys & MAXWORD) * sizeof(*polyIndices)) != SUCCESS) {
			goto done;
		}

		if (p_storage->Read(&numTextureIndices, sizeof(numTextureIndices)) != SUCCESS) {
			goto done;
		}

		if (numTextureIndices > 0) {
			textureIndices = new LegoU32[numPolys & MAXWORD][_countof(*textureIndices)];
			if (p_storage->Read(textureIndices, (numPolys & MAXWORD) * sizeof(*textureIndices)) != SUCCESS) {
				goto done;
			}
		}
		else {
			textureIndices = NULL;
		}

		mesh = new LegoMesh();

		if (mesh->Read(p_storage) != SUCCESS) {
			goto done;
		}

		switch (mesh->GetShading()) {
		case LegoMesh::e_flat:
			shadingModel = Tgl::Flat;
			break;
		case LegoMesh::e_wireframe:
			shadingModel = Tgl::Wireframe;
			break;
		default:
			shadingModel = Tgl::Gouraud;
		}

		m_numVertices += numVertices & MAXWORD;

		textureName = mesh->GetTextureName();
		materialName = mesh->GetMaterialName();

		if (FUN_100aae20(textureName) || FUN_100aae20(materialName)) {
			meshIndex = meshUnd1;
			meshUnd1--;
		}
		else {
			meshIndex = meshUnd2;
			meshUnd2++;
		}

		m_melems[meshIndex].m_tglMesh = m_meshBuilder->CreateMesh(
			numPolys & MAXWORD,
			numVertices & MAXWORD,
			vertices,
			normals,
			textureVertices,
			polyIndices,
			textureIndices,
			shadingModel
		);

		if (m_melems[meshIndex].m_tglMesh == NULL) {
			goto done;
		}

		m_melems[meshIndex].m_tglMesh->SetShadingModel(shadingModel);

		if (textureName != NULL) {
			if (mesh->GetUnknown0x21()) {
				LegoROI::FUN_100a9cf0(textureName, paletteEntries, _countof(paletteEntries));
			}

			textureInfo = p_textureContainer->Get(mesh->GetTextureName());

			if (textureInfo == NULL) {
				goto done;
			}

			m_melems[meshIndex].m_tglMesh->SetColor(1.0F, 1.0F, 1.0F, 0.0F);
			LegoTextureInfo::SetGroupTexture(m_melems[meshIndex].m_tglMesh, textureInfo);
			m_melems[meshIndex].m_unk0x04 = TRUE;
		}
		else {
			LegoFloat red = 1.0F;
			LegoFloat green = 0.0F;
			LegoFloat blue = 1.0F;
			LegoFloat alpha = 0.0F;

			if (mesh->GetUnknown0x21()) {
				LegoROI::FUN_100a9bf0(materialName, red, green, blue, alpha);
			}
			else {
				red = mesh->GetColor().GetRed() / 255.0;
				green = mesh->GetColor().GetGreen() / 255.0;
				blue = mesh->GetColor().GetBlue() / 255.0;
				alpha = mesh->GetAlpha();
			}

			m_melems[meshIndex].m_tglMesh->SetColor(red, green, blue, alpha);
		}

		if (mesh->GetUnknown0x0d() > 0) {
			IDirect3DRMMesh* mesh;
			D3DRMGROUPINDEX index;
			GetMeshData(mesh, index, m_melems[meshIndex].m_tglMesh);
			mesh->SetGroupMaterial(index, g_unk0x101013d4);
		}

		if (mesh != NULL) {
			delete mesh;
			mesh = NULL;
		}
		if (polyIndices != NULL) {
			delete[] polyIndices;
			polyIndices = NULL;
		}
		if (textureIndices != NULL) {
			delete[] textureIndices;
			textureIndices = NULL;
		}
	}

	m_unk0x1c = meshUnd2;

	if (textureVertices != NULL) {
		delete[] textureVertices;
	}
	if (normals != NULL) {
		delete[] normals;
	}
	if (vertices != NULL) {
		delete[] vertices;
	}

	return SUCCESS;

done:
	if (normals != NULL) {
		delete[] normals;
	}
	if (vertices != NULL) {
		delete[] vertices;
	}
	if (textureVertices != NULL) {
		delete[] textureVertices;
	}
	if (mesh != NULL) {
		delete mesh;
	}
	if (polyIndices != NULL) {
		delete[] polyIndices;
	}
	if (textureIndices != NULL) {
		delete[] textureIndices;
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100aabb0
LegoLOD* LegoLOD::Clone(Tgl::Renderer* p_renderer)
{
	LegoLOD* dupLod = new LegoLOD(p_renderer);

	dupLod->m_meshBuilder = m_meshBuilder->Clone();
	dupLod->m_melems = new Mesh[m_numMeshes];

	for (LegoU32 i = 0; i < m_numMeshes; i++) {
		dupLod->m_melems[i].m_tglMesh = m_melems[i].m_tglMesh->ShallowClone(dupLod->m_meshBuilder);
		dupLod->m_melems[i].m_unk0x04 = m_melems[i].m_unk0x04;
	}

	dupLod->m_unk0x08 = m_unk0x08;
	dupLod->m_numMeshes = m_numMeshes;
	dupLod->m_numVertices = m_numVertices;
	dupLod->m_numPolys = m_numPolys;
	dupLod->m_unk0x1c = m_unk0x1c;

	return dupLod;
}

// FUNCTION: LEGO1 0x100aacb0
LegoResult LegoLOD::FUN_100aacb0(LegoFloat p_red, LegoFloat p_green, LegoFloat p_blue, LegoFloat p_alpha)
{
	for (LegoU32 i = m_unk0x1c; i < m_numMeshes; i++) {
		if (!m_melems[i].m_unk0x04) {
			m_melems[i].m_tglMesh->SetColor(p_red, p_green, p_blue, p_alpha);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100aad00
LegoResult LegoLOD::FUN_100aad00(LegoTextureInfo* p_textureInfo)
{
	for (LegoU32 i = m_unk0x1c; i < m_numMeshes; i++) {
		if (m_melems[i].m_unk0x04) {
			LegoTextureInfo::SetGroupTexture(m_melems[i].m_tglMesh, p_textureInfo);
			m_melems[i].m_tglMesh->SetColor(1.0F, 1.0F, 1.0F, 0.0F);
			m_melems[i].m_unk0x04 = TRUE;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100aae20
LegoBool LegoLOD::FUN_100aae20(const LegoChar* p_name)
{
	if (p_name != NULL) {
		if (!strnicmp(p_name, g_unk0x101013dc, strlen(g_unk0x101013dc))) {
			return TRUE;
		}
	}

	return FALSE;
}

inline BOOL GetMeshData(IDirect3DRMMesh*& mesh, D3DRMGROUPINDEX& index, Tgl::Mesh* pMesh)
{
	mesh = ((TglImpl::MeshImpl*) pMesh)->ImplementationData()->groupMesh;
	index = ((TglImpl::MeshImpl*) pMesh)->ImplementationData()->groupIndex;
	return FALSE;
}

inline IDirect3DRM2* GetD3DRM(Tgl::Renderer* pRenderer)
{
	return ((TglImpl::RendererImpl*) pRenderer)->ImplementationData();
}
