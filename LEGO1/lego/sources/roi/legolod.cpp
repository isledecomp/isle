
#include "legolod.h"

#include "legoroi.h"
#include "misc/legocontainer.h"
#include "misc/legostorage.h"
#include "shape/legomesh.h"
#include "tgl/d3drm/impl.h"

DECOMP_SIZE_ASSERT(LODObject, 0x04)
DECOMP_SIZE_ASSERT(ViewLOD, 0x0c)
DECOMP_SIZE_ASSERT(LegoLOD, 0x20)
DECOMP_SIZE_ASSERT(LegoLOD::Mesh, 0x08)

// GLOBAL: LEGO1 0x101013d4
// GLOBAL: BETA10 0x10207230
LPDIRECT3DRMMATERIAL g_unk0x101013d4 = NULL;

// GLOBAL: LEGO1 0x101013dc
const char* g_InhPrefix = "inh";

#ifdef BETA10
inline BOOL GetD3DRM_legolod(IDirect3DRM2*& d3drm, Tgl::Renderer* pRenderer);
#else
inline IDirect3DRM2* GetD3DRM_legolod(Tgl::Renderer* pRenderer);
#endif
inline BOOL GetMeshData(IDirect3DRMMesh*& mesh, D3DRMGROUPINDEX& index, Tgl::Mesh* pMesh);

// FUNCTION: LEGO1 0x100aa380
// FUNCTION: BETA10 0x1018ce90
LegoLOD::LegoLOD(Tgl::Renderer* p_renderer) : ViewLOD(p_renderer)
{
	if (g_unk0x101013d4 == NULL) {
#ifdef BETA10
		IDirect3DRM2* d3drm = NULL;
		assert((p_renderer != NULL));
		GetD3DRM_legolod(d3drm, p_renderer);
		if (d3drm->CreateMaterial(10.0, &g_unk0x101013d4)) {
			assert(0);
		}
#else
		GetD3DRM_legolod(p_renderer)->CreateMaterial(10.0, &g_unk0x101013d4);
#endif
	}

	m_melems = NULL;
	m_numMeshes = 0;
	m_numVertices = 0;
	m_numPolys = 0;
	m_meshOffset = 0;
}

// FUNCTION: LEGO1 0x100aa450
// FUNCTION: BETA10 0x1018d017
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
// STUB: BETA10 0x1018d15d
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

	LegoU32 i, indexBackwards, indexForwards, tempNumVertsAndNormals;
	unsigned char paletteEntries[256];

	if (p_storage->Read(&m_flags, sizeof(LegoU32)) != SUCCESS) {
		goto done;
	}

	if (SkipReadingData()) {
		return SUCCESS;
	}

	m_meshBuilder = p_renderer->CreateMeshBuilder();

	if (p_storage->Read(&m_numMeshes, sizeof(LegoU32)) != SUCCESS) {
		goto done;
	}

	if (m_numMeshes == 0) {
		ClearFlag(c_hasMesh);
		return SUCCESS;
	}

	SetFlag(c_hasMesh);

	m_melems = new Mesh[m_numMeshes];
	memset(m_melems, 0, sizeof(*m_melems) * m_numMeshes);

	indexBackwards = m_numMeshes - 1;
	indexForwards = 0;

	if (p_storage->Read(&tempNumVertsAndNormals, sizeof(LegoU32)) != SUCCESS) {
		goto done;
	}

	numVerts = *((LegoU16*) &tempNumVertsAndNormals) & MAXSHORT;
	numNormals = (*((LegoU16*) &tempNumVertsAndNormals + 1) >> 1) & MAXSHORT;

	if (p_storage->Read(&numTextureVertices, sizeof(LegoS32)) != SUCCESS) {
		goto done;
	}

	if (numVerts > 0) {
		vertices = new float[numVerts][sizeOfArray(*vertices)];
		if (p_storage->Read(vertices, numVerts * 3 * sizeof(float)) != SUCCESS) {
			goto done;
		}
	}

	if (numNormals > 0) {
		normals = new float[numNormals][sizeOfArray(*normals)];
		if (p_storage->Read(normals, numNormals * 3 * sizeof(float)) != SUCCESS) {
			goto done;
		}
	}

	if (numTextureVertices > 0) {
		textureVertices = new float[numTextureVertices][sizeOfArray(*textureVertices)];
		if (p_storage->Read(textureVertices, numTextureVertices * 2 * sizeof(float)) != SUCCESS) {
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

		m_numPolys += numPolys & USHRT_MAX;

		if (p_storage->Read(&numVertices, 2) != SUCCESS) {
			goto done;
		}

		polyIndices = new LegoU32[numPolys & USHRT_MAX][sizeOfArray(*polyIndices)];
		if (p_storage->Read(polyIndices, (numPolys & USHRT_MAX) * 3 * sizeof(LegoU32)) != SUCCESS) {
			goto done;
		}

		if (p_storage->Read(&numTextureIndices, sizeof(numTextureIndices)) != SUCCESS) {
			goto done;
		}

		if (numTextureIndices > 0) {
			textureIndices = new LegoU32[numPolys & USHRT_MAX][sizeOfArray(*textureIndices)];
			if (p_storage->Read(textureIndices, (numPolys & USHRT_MAX) * 3 * sizeof(LegoU32)) != SUCCESS) {
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

		m_numVertices += numVertices & USHRT_MAX;

		textureName = mesh->GetTextureName();
		materialName = mesh->GetMaterialName();

		if (HasInhPrefix(textureName) || HasInhPrefix(materialName)) {
			meshIndex = indexBackwards;
			indexBackwards--;
		}
		else {
			meshIndex = indexForwards;
			indexForwards++;
		}

		m_melems[meshIndex].m_tglMesh = m_meshBuilder->CreateMesh(
			numPolys & USHRT_MAX,
			numVertices & USHRT_MAX,
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
			if (mesh->GetUseAlias()) {
				LegoROI::GetPaletteEntries(textureName, paletteEntries, sizeOfArray(paletteEntries));
			}

			textureInfo = p_textureContainer->Get(mesh->GetTextureName());

			if (textureInfo == NULL) {
				goto done;
			}

			m_melems[meshIndex].m_tglMesh->SetColor(1.0F, 1.0F, 1.0F, 0.0F);
			LegoTextureInfo::SetGroupTexture(m_melems[meshIndex].m_tglMesh, textureInfo);
			m_melems[meshIndex].m_textured = TRUE;
		}
		else {
			LegoFloat red = 1.0F;
			LegoFloat green = 0.0F;
			LegoFloat blue = 1.0F;
			LegoFloat alpha = 0.0F;

			if (mesh->GetUseAlias()) {
				LegoROI::GetRGBAColor(materialName, red, green, blue, alpha);
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

	m_meshOffset = indexForwards;

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
// FUNCTION: BETA10 0x1018e02a
LegoLOD* LegoLOD::Clone(Tgl::Renderer* p_renderer)
{
	LegoLOD* dupLod = new LegoLOD(p_renderer);

	dupLod->m_meshBuilder = m_meshBuilder->Clone();
	dupLod->m_melems = new Mesh[m_numMeshes];

	assert(dupLod->m_melems);

	for (LegoU32 i = 0; i < m_numMeshes; i++) {
		dupLod->m_melems[i].m_tglMesh = m_melems[i].m_tglMesh->ShallowClone(dupLod->m_meshBuilder);
		dupLod->m_melems[i].m_textured = m_melems[i].m_textured;
	}

	dupLod->m_flags = m_flags;
	dupLod->m_numMeshes = m_numMeshes;
	dupLod->m_numVertices = m_numVertices;
	dupLod->m_numPolys = m_numPolys;
	dupLod->m_meshOffset = m_meshOffset;

	return dupLod;
}

// FUNCTION: LEGO1 0x100aacb0
LegoResult LegoLOD::SetColor(LegoFloat p_red, LegoFloat p_green, LegoFloat p_blue, LegoFloat p_alpha)
{
	for (LegoU32 i = m_meshOffset; i < m_numMeshes; i++) {
		if (!m_melems[i].m_textured) {
			m_melems[i].m_tglMesh->SetColor(p_red, p_green, p_blue, p_alpha);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100aad00
// FUNCTION: BETA10 0x1018e241
LegoResult LegoLOD::SetTextureInfo(LegoTextureInfo* p_textureInfo)
{
	using Tgl::Succeeded;

	for (LegoU32 i = m_meshOffset; i < m_numMeshes; i++) {
		if (m_melems[i].m_textured) {
#ifdef BETA10
			// This function likely had a different signature in BETA10
			Tgl::Result tglResult = m_melems[i].m_tglMesh->SetTexture((const Tgl::Texture *)p_textureInfo);
			// clang-format off
			assert(Succeeded( tglResult ));
			// clang-format on
#else
			LegoTextureInfo::SetGroupTexture(m_melems[i].m_tglMesh, p_textureInfo);
#endif
			m_melems[i].m_tglMesh->SetColor(1.0F, 1.0F, 1.0F, 0.0F);
			m_melems[i].m_textured = TRUE;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100aad70
LegoResult LegoLOD::UpdateTextureInfo(LegoTextureInfo* p_textureInfo)
{
	for (LegoU32 i = m_meshOffset; i < m_numMeshes; i++) {
		if (m_melems[i].m_textured) {
			LegoTextureInfo::SetGroupTexture(m_melems[i].m_tglMesh, p_textureInfo);
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100aadc0
LegoResult LegoLOD::GetTextureInfo(LegoTextureInfo*& p_textureInfo)
{
	for (LegoU32 i = m_meshOffset; i < m_numMeshes; i++) {
		if (m_melems[i].m_textured) {
			if (LegoTextureInfo::GetGroupTexture(m_melems[i].m_tglMesh, p_textureInfo) == TRUE) {
				return SUCCESS;
			}
		}
	}

	return FAILURE;
}

// FUNCTION: LEGO1 0x100aae20
LegoBool LegoLOD::HasInhPrefix(const LegoChar* p_name)
{
	if (p_name != NULL) {
		if (!strnicmp(p_name, g_InhPrefix, strlen(g_InhPrefix))) {
			return TRUE;
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x100aae60
// FUNCTION: BETA10 0x1018e50f
void LegoLOD::ClearMeshOffset()
{
	m_meshOffset = 0;
}

// FUNCTION: BETA10 0x1018dfc4
inline BOOL GetMeshData(IDirect3DRMMesh*& mesh, D3DRMGROUPINDEX& index, Tgl::Mesh* p_tglElem)
{
	assert(p_tglElem);
	TglImpl::MeshImpl* meshImpl = (TglImpl::MeshImpl*) p_tglElem;
	// Note: Diff in BETA10 (thunked in recompile but not in orig)
	mesh = meshImpl->ImplementationData()->groupMesh;
	index = meshImpl->ImplementationData()->groupIndex;
	return FALSE;
}

#ifdef BETA10
// FUNCTION: BETA10 0x1018cfc5
inline BOOL GetD3DRM_legolod(IDirect3DRM2*& d3drm, Tgl::Renderer* p_tglRenderer)
{
	// Note: Code duplication with viewmanager.cpp:GetD3DRM()
	assert(p_tglRenderer);
	TglImpl::RendererImpl* renderer = (TglImpl::RendererImpl*) p_tglRenderer;
	// Note: Diff in BETA10 (thunked in recompile but not in orig)
	d3drm = renderer->ImplementationData();
	return 0;
}
#else
inline IDirect3DRM2* GetD3DRM_legolod(Tgl::Renderer* pRenderer)
{
	return ((TglImpl::RendererImpl*) pRenderer)->ImplementationData();
}
#endif
