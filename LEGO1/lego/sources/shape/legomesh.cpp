#include "legomesh.h"

#include "misc/legostorage.h"

DECOMP_SIZE_ASSERT(LegoMeshUnkComponent, 0x1c)
DECOMP_SIZE_ASSERT(LegoMesh, 0x24)

// FUNCTION: LEGO1 0x100d3810
LegoMesh::LegoMesh()
{
	m_alpha = 0.0F;
	m_shading = e_flat;
	m_unk0x14 = 0;
	m_textureName = NULL;
	m_unk0x0d = 0;
	m_unk0x10 = NULL;
	m_unk0x20 = 0;
	m_unk0x21 = FALSE;
	m_materialName = NULL;
}

// FUNCTION: LEGO1 0x100d3860
LegoMesh::~LegoMesh()
{
	if (m_textureName != NULL) {
		delete[] m_textureName;
	}

	if (m_materialName != NULL) {
		delete[] m_materialName;
	}

	if (m_unk0x10 != NULL) {
		delete m_unk0x10;
	}
}

// FUNCTION: LEGO1 0x100d38f0
LegoResult LegoMesh::Read(LegoStorage* p_storage)
{
	LegoResult result;
	LegoU32 textureLength, materialLength;
	if ((result = m_color.Read(p_storage)) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_alpha, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_shading, sizeof(LegoU8))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_unk0x0d, sizeof(LegoU8))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_unk0x20, sizeof(undefined))) != SUCCESS) {
		return result;
	}
	if ((result = p_storage->Read(&m_unk0x21, sizeof(LegoU8))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&textureLength, sizeof(LegoU32))) != SUCCESS) {
		return result;
	}
	if (textureLength) {
		m_textureName = new LegoChar[textureLength + 1];

		if ((result = p_storage->Read(m_textureName, textureLength)) != SUCCESS) {
			return result;
		}

		m_textureName[textureLength] = '\0';
		strlwr(m_textureName);
	}

	if ((result = p_storage->Read(&materialLength, sizeof(LegoU32))) != SUCCESS) {
		return result;
	}
	if (materialLength) {
		m_materialName = new LegoChar[materialLength + 1];

		if ((result = p_storage->Read(m_materialName, materialLength)) != SUCCESS) {
			return result;
		}

		m_materialName[materialLength] = '\0';
		strlwr(m_materialName);
	}

	return SUCCESS;
}
