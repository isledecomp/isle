
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
LPDIRECT3DRMMATERIAL g_lodMaterial = NULL;

// GLOBAL: LEGO1 0x101013dc
// GLOBAL: BETA10 0x10207238
const char* g_InhPrefix = "inh";

#ifdef BETA10
inline BOOL GetD3DRM_legolod(IDirect3DRM2*& d3drm, Tgl::Renderer* pRenderer);
#else
inline IDirect3DRM2* GetD3DRM_legolod(Tgl::Renderer* pRenderer);
#endif
inline BOOL GetMeshData(IDirect3DRMMesh** mesh, D3DRMGROUPINDEX* index, Tgl::Mesh* pMesh);

// FUNCTION: LEGO1 0x100aa380
// FUNCTION: BETA10 0x1018ce90
LegoLOD::LegoLOD(Tgl::Renderer* p_renderer) : ViewLOD(p_renderer)
{
	if (g_lodMaterial == NULL) {
#ifdef BETA10
		IDirect3DRM2* d3drm = NULL;
		assert((p_renderer != NULL));
		GetD3DRM_legolod(d3drm, p_renderer);
		if (d3drm->CreateMaterial(10.0, &g_lodMaterial)) {
			assert(0);
		}
#else
		GetD3DRM_legolod(p_renderer)->CreateMaterial(10.0, &g_lodMaterial);
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

#ifdef BETA10
/// This class does not exist in LEGO1.
class UnknownBeta0x1018e7e0 {
public:
	// FUNCTION: BETA10 0x1018e7e0
	UnknownBeta0x1018e7e0()
	{
		m_unk0x00 = 0;
		m_unk0x04 = 0;
		m_unk0x08 = 0;
		m_unk0x0c = 0;
		m_unk0x10 = 0;
		m_unk0x14 = 0;
		m_unk0x18 = 0;
	}

	// STUB: BETA10 0x1018e840
	undefined4 BETA10_1018e840(LegoStorage* p_storage) { return 0; }

	undefined4 m_unk0x00;
	undefined4 m_unk0x04;
	undefined4 m_unk0x08;
	undefined4 m_unk0x0c;
	undefined4 m_unk0x10;
	undefined4 m_unk0x14;
	undefined4 m_unk0x18;
	undefined4 m_unk0x1c;
};
#endif

// FUNCTION: LEGO1 0x100aa510
// FUNCTION: BETA10 0x1018d15d
LegoResult LegoLOD::Read(Tgl::Renderer* p_renderer, LegoTextureContainer* p_textureContainer, LegoStorage* p_storage)
{
	using Tgl::Succeeded;

	float(*normals)[3] = NULL;
	float(*vertices)[3] = NULL;
	float(*textureVertices)[2] = NULL;
	LegoS32 numVerts = 0;
	LegoS32 numNormals = 0;
	LegoS32 numTextureVertices = 0;
	LegoMesh* legoMesh = NULL;
	LegoU32(*polyIndices)[3] = NULL;
	LegoU32(*textureIndices)[3] = NULL;
	LegoTextureInfo* textureInfo = NULL;
	LegoU8 local4c = 0; // BETA10 only, only written, never read
	LegoU32 numPolys, numVertices, numTextureIndices, meshIndex;
	LegoU32 i, indexBackwards, indexForwards, tempNumVertsAndNormals;
	LegoFloat red, green, blue, alpha;
	IDirect3DRMMesh* d3dmesh;
	D3DRMGROUPINDEX index;

	unsigned char paletteEntries[256];

	if (p_storage->Read(&m_flags, sizeof(LegoU32)) != SUCCESS) {
		goto done;
	}

	if (SkipReadingData()) {
#ifdef BETA10
		// There was an additional field of the correct type here in BETA10
		m_flags = (unsigned int) new UnknownBeta0x1018e7e0();
		if (((UnknownBeta0x1018e7e0*) m_flags)->BETA10_1018e840(p_storage)) {
			assert(0);
			return FAILURE;
		}
#endif
		return SUCCESS;
	}

	m_meshBuilder = p_renderer->CreateMeshBuilder();

	if (p_storage->Read(&m_numMeshes, sizeof(LegoU32)) != SUCCESS) {
		goto done;
	}

	if (m_numMeshes == 0) {
#ifndef BETA10
		ClearFlag(c_hasMesh);
#endif
		return SUCCESS;
	}

#ifndef BETA10
	SetFlag(c_hasMesh);
#endif

	m_melems = new Mesh[m_numMeshes];
	memset(m_melems, 0, sizeof(*m_melems) * m_numMeshes);

	indexBackwards = m_numMeshes - 1;
	indexForwards = 0;

	if (p_storage->Read(&tempNumVertsAndNormals, sizeof(LegoU32)) != SUCCESS) {
		assertIfBeta10(0);
		goto done;
	}

	// TODO: Can't get this one right
	numVerts = *((LegoU16*) &tempNumVertsAndNormals) & MAXSHORT;
	numNormals = (*((LegoU16*) &tempNumVertsAndNormals + 1) >> 1) & MAXSHORT;

	if (p_storage->Read(&numTextureVertices, sizeof(LegoS32)) != SUCCESS) {
		assertIfBeta10(0);
		goto done;
	}

	if (numVerts > 0) {
		vertices = new float[numVerts][sizeOfArray(*vertices)];
		if (p_storage->Read(vertices, numVerts * 3 * sizeof(float)) != SUCCESS) {
			// LINE: BETA10 0x1018d443
			assertIfBeta10(0);
			goto done;
		}
	}

	if (numNormals > 0) {
		normals = new float[numNormals][sizeOfArray(*normals)];
		if (p_storage->Read(normals, numNormals * 3 * sizeof(float)) != SUCCESS) {
			assertIfBeta10(0);
			goto done;
		}
	}

	if (numTextureVertices > 0) {
		textureVertices = new float[numTextureVertices][sizeOfArray(*textureVertices)];
		if (p_storage->Read(textureVertices, numTextureVertices * 2 * sizeof(float)) != SUCCESS) {
			// LINE: BETA10 0x1018d513
			assertIfBeta10(0);
			goto done;
		}
	}

	for (i = 0; i < m_numMeshes; i++) {
		local4c = 0;
		const LegoChar *textureName, *materialName;
		Tgl::ShadingModel shadingModel;

		if (p_storage->Read(&numPolys, 2) != SUCCESS) {
			assertIfBeta10(0);
			goto done;
		}

		m_numPolys += numPolys & USHRT_MAX;

		if (p_storage->Read(&numVertices, 2) != SUCCESS) {
			assertIfBeta10(0);
			goto done;
		}

		polyIndices = new LegoU32[numPolys & USHRT_MAX][sizeOfArray(*polyIndices)];
		if (p_storage->Read(polyIndices, (numPolys & USHRT_MAX) * 3 * sizeof(LegoU32)) != SUCCESS) {
			assertIfBeta10(0);
			goto done;
		}

		if (p_storage->Read(&numTextureIndices, sizeof(numTextureIndices)) != SUCCESS) {
			assertIfBeta10(0);
			goto done;
		}

		if (numTextureIndices > 0) {
			textureIndices = new LegoU32[numPolys & USHRT_MAX][sizeOfArray(*textureIndices)];
			if (p_storage->Read(textureIndices, (numPolys & USHRT_MAX) * 3 * sizeof(LegoU32)) != SUCCESS) {
					assertIfBeta10(0);
				goto done;
			}
		}
		else {
			textureIndices = NULL;
		}

		legoMesh = new LegoMesh();

		if (legoMesh->Read(p_storage) != SUCCESS) {
			assertIfBeta10(0);
			goto done;
		}

		switch (legoMesh->GetShading()) {
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

		textureName = legoMesh->GetTextureName();
		materialName = legoMesh->GetMaterialName();

		if (HasInhPrefix(textureName) || HasInhPrefix(materialName)) {
			meshIndex = indexBackwards;
			indexBackwards--;
		}
		else {
			local4c = 1;
			meshIndex = indexForwards;
			indexForwards++;
		}

		Tgl::MeshBuilder* locMesh = m_meshBuilder;
		assert(locMesh);

		m_melems[meshIndex].m_tglMesh = locMesh->CreateMesh(
			numPolys & USHRT_MAX,
			numVertices & USHRT_MAX,
			vertices,
			normals,
			textureVertices,
			polyIndices,
			textureIndices,
			shadingModel
			// LINE: LEGO1 0x100aa885
		);

		if (m_melems[meshIndex].m_tglMesh == NULL) {
			assertIfBeta10(0);
			goto done;
		}

		Tgl::Result tglResult = m_melems[meshIndex].m_tglMesh->SetShadingModel(shadingModel);

		// clang-format off
		assert(Succeeded( tglResult ));
		// clang-format on

		if (textureName != NULL) {
			if (legoMesh->GetUseAlias() &&
				LegoROI::GetPaletteEntries(textureName, paletteEntries, sizeOfArray(paletteEntries))) {
#ifdef BETA10
				textureName = (const LegoChar*) paletteEntries;
#endif
			}

			textureInfo = p_textureContainer->Get(legoMesh->GetTextureName());

			if (textureInfo == NULL) {
				assertIfBeta10(0);
				goto done;
			}

			tglResult = m_melems[meshIndex].m_tglMesh->SetColor(1.0F, 1.0F, 1.0F, 0.0F);
			// clang-format off
			assert(Succeeded( tglResult ));
			// clang-format on

#ifdef BETA10
			// This typecast is invalid, `textureInfo` had a different type in BETA10
			tglResult = m_melems[meshIndex].m_tglMesh->SetTexture((TglImpl::TextureImpl*) textureInfo);
			// clang-format off
			assert(Succeeded( tglResult ));
			// clang-format on
#else
			LegoTextureInfo::SetGroupTexture(m_melems[meshIndex].m_tglMesh, textureInfo);
#endif

			m_melems[meshIndex].m_textured = TRUE;
		}
		else {
			red = 1.0F;
			// LINE: BETA10 0x1018db2d
			green = 0.0F;
			blue = 1.0F;
			alpha = 0.0F;

			if (legoMesh->GetUseAlias()) {
				LegoROI::GetRGBAColor(materialName, red, green, blue, alpha);
			}
			else {
				red = legoMesh->GetColor().GetRed() / 255.0;
				green = legoMesh->GetColor().GetGreen() / 255.0;
				blue = legoMesh->GetColor().GetBlue() / 255.0;
				alpha = legoMesh->GetAlpha();
			}

			tglResult = m_melems[meshIndex].m_tglMesh->SetColor(red, green, blue, alpha);
			// clang-format off
			// LINE: BETA10 0x1018dc72
			assert(Succeeded( tglResult ));
			// clang-format on
		}

		if (legoMesh->GetUnknown0x0d() > 0) {
			GetMeshData(&d3dmesh, &index, m_melems[meshIndex].m_tglMesh);
			d3dmesh->SetGroupMaterial(index, g_lodMaterial);
		}

		if (legoMesh != NULL) {
			delete legoMesh;
			legoMesh = NULL;
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

	// LINE: LEGO1 0x100aab45
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
	if (legoMesh != NULL) {
		delete legoMesh;
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
			Tgl::Result tglResult = m_melems[i].m_tglMesh->SetTexture((const Tgl::Texture*) p_textureInfo);
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
// FUNCTION: BETA10 0x1018e32c
LegoResult LegoLOD::UpdateTextureInfo(LegoTextureInfo* p_textureInfo)
{
	using Tgl::Succeeded;

	for (LegoU32 i = m_meshOffset; i < m_numMeshes; i++) {
		if (m_melems[i].m_textured) {
#ifdef BETA10
			// This function likely had a different signature in BETA10
			Tgl::Result tglResult = m_melems[i].m_tglMesh->SetTexture((const Tgl::Texture*) p_textureInfo);
			// clang-format off
			assert(Succeeded( tglResult ));
			// clang-format on
#else
			LegoTextureInfo::SetGroupTexture(m_melems[i].m_tglMesh, p_textureInfo);
#endif
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
// FUNCTION: BETA10 0x1018e46d
LegoBool LegoLOD::HasInhPrefix(const LegoChar* p_name)
{
	if (p_name != NULL && !strnicmp(p_name, g_InhPrefix, strlen(g_InhPrefix))) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

// FUNCTION: LEGO1 0x100aae60
// FUNCTION: BETA10 0x1018e50f
void LegoLOD::ClearMeshOffset()
{
	m_meshOffset = 0;
}

// FUNCTION: BETA10 0x1018dfc4
inline BOOL GetMeshData(IDirect3DRMMesh** mesh, D3DRMGROUPINDEX* index, Tgl::Mesh* p_tglElem)
{
	assert(p_tglElem);
	TglImpl::MeshImpl* meshImpl = (TglImpl::MeshImpl*) p_tglElem;
	// Note: Diff in BETA10 (thunked in recompile but not in orig)
	*mesh = meshImpl->ImplementationData()->groupMesh;
	*index = meshImpl->ImplementationData()->groupIndex;
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
