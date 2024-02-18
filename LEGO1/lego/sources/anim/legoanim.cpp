#include "legoanim.h"

DECOMP_SIZE_ASSERT(LegoAnimKey, 0x08)
DECOMP_SIZE_ASSERT(LegoTranslationKey, 0x14)
DECOMP_SIZE_ASSERT(LegoRotationKey, 0x18)
DECOMP_SIZE_ASSERT(LegoScaleKey, 0x14)
DECOMP_SIZE_ASSERT(LegoMorphKey, 0x0c)
DECOMP_SIZE_ASSERT(LegoAnim, 0x18)

// FUNCTION: LEGO1 0x1009f900
LegoAnimKey::LegoAnimKey()
{
	m_unk0x00 = 0;
	m_unk0x04 = 0;
}

// STUB: LEGO1 0x1009f910
LegoResult LegoAnimKey::Read(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009f990
LegoTranslationKey::LegoTranslationKey()
{
	m_x = 0.0F;
	m_y = 0.0F;
	m_z = 0.0F;
}

// STUB: LEGO1 0x1009f9b0
LegoResult LegoTranslationKey::Read(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009faa0
LegoRotationKey::LegoRotationKey()
{
	m_angle = 1.0F;
	m_x = 0.0F;
	m_y = 0.0F;
	m_z = 0.0F;
}

// STUB: LEGO1 0x1009fac0
LegoResult LegoRotationKey::Read(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009fba0
LegoScaleKey::LegoScaleKey()
{
	m_x = 1.0F;
	m_y = 1.0F;
	m_z = 1.0F;
}

// STUB: LEGO1 0x1009fbc0
LegoResult LegoScaleKey::Read(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100a0f60
LegoMorphKey::LegoMorphKey()
{
	m_name = NULL;
}

// STUB: LEGO1 0x100a0f70
LegoResult LegoMorphKey::Read(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x1009fcf0
LegoAnimNodeData::LegoAnimNodeData()
{
	// TODO
}

// FUNCTION: LEGO1 0x1009fda0
LegoAnimNodeData::~LegoAnimNodeData()
{
	if (m_name) {
		delete[] m_name;
	}
	if (m_translationKeys) {
		delete[] m_translationKeys;
	}
	if (m_rotationKeys) {
		delete[] m_rotationKeys;
	}
	if (m_scaleKeys) {
		delete[] m_scaleKeys;
	}
	if (m_morphKeys) {
		delete[] m_morphKeys;
	}
}

// FUNCTION: LEGO1 0x1009fe60
LegoResult LegoAnimNodeData::Read(LegoStorage* p_storage)
{
	LegoResult result;

	LegoU32 length;
	if ((result = p_storage->Read(&length, sizeof(length))) != SUCCESS) {
		return result;
	}

	if (m_name) {
		delete[] m_name;
		m_name = NULL;
	}
	if (length) {
		m_name = new LegoChar[length + 1];
		if ((result = p_storage->Read(m_name, length)) != SUCCESS) {
			return result;
		}
		m_name[length] = '\0';
	}

	LegoU32 i;

	if ((result = p_storage->Read(&m_numTranslationKeys, sizeof(m_numTranslationKeys))) != SUCCESS) {
		return result;
	}
	if (m_translationKeys) {
		delete[] m_translationKeys;
		m_translationKeys = NULL;
	}
	if (m_numTranslationKeys) {
		m_translationKeys = new LegoTranslationKey[m_numTranslationKeys];
		for (i = 0; i < m_numTranslationKeys; i++) {
			if ((result = m_translationKeys[i].Read(p_storage)) != SUCCESS) {
				return result;
			}
		}
	}

	if ((result = p_storage->Read(&m_numRotationKeys, sizeof(m_numRotationKeys))) != SUCCESS) {
		return result;
	}
	if (m_rotationKeys) {
		delete[] m_rotationKeys;
		m_rotationKeys = NULL;
	}
	if (m_numRotationKeys) {
		m_rotationKeys = new LegoRotationKey[m_numRotationKeys];
		for (i = 0; i < m_numRotationKeys; i++) {
			if ((result = m_rotationKeys[i].Read(p_storage)) != SUCCESS) {
				return result;
			}
		}
	}

	if ((result = p_storage->Read(&m_numScaleKeys, sizeof(m_numScaleKeys))) != SUCCESS) {
		return result;
	}
	if (m_scaleKeys) {
		delete[] m_scaleKeys;
		m_scaleKeys = NULL;
	}
	if (m_numScaleKeys) {
		m_scaleKeys = new LegoScaleKey[m_numScaleKeys];
		for (i = 0; i < m_numScaleKeys; i++) {
			if ((result = m_scaleKeys[i].Read(p_storage)) != SUCCESS) {
				return result;
			}
		}
	}

	if ((result = p_storage->Read(&m_numMorphKeys, sizeof(m_numMorphKeys))) != SUCCESS) {
		return result;
	}
	if (m_morphKeys) {
		delete[] m_morphKeys;
		m_morphKeys = NULL;
	}
	if (m_numMorphKeys) {
		m_morphKeys = new LegoMorphKey[m_numMorphKeys];
		for (i = 0; i < m_numMorphKeys; i++) {
			if ((result = m_morphKeys[i].Read(p_storage)) != SUCCESS) {
				return result;
			}
		}
	}

	return SUCCESS;
}

// STUB: LEGO1 0x100a01e0
LegoResult LegoAnimNodeData::Write(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100a0b30
LegoAnim::LegoAnim()
{
	m_duration = 0;
	m_unk0x0c = 0;
	m_unk0x10 = 0;
	m_unk0x14 = 0;
}

// STUB: LEGO1 0x100a0bc0
LegoAnim::~LegoAnim()
{
	// TODO
}

// STUB: LEGO1 0x100a0c70
LegoResult LegoAnim::Read(LegoStorage* p_storage, LegoS32)
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x100a0e30
LegoResult LegoAnim::Write(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}
