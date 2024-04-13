#include "legoanim.h"

#include "mxgeometry/mxmatrix.h"

#include <limits.h>

DECOMP_SIZE_ASSERT(LegoAnimKey, 0x08)
DECOMP_SIZE_ASSERT(LegoTranslationKey, 0x14)
DECOMP_SIZE_ASSERT(LegoRotationKey, 0x18)
DECOMP_SIZE_ASSERT(LegoScaleKey, 0x14)
DECOMP_SIZE_ASSERT(LegoMorphKey, 0x0c)
DECOMP_SIZE_ASSERT(LegoUnknownKey, 0x0c)
DECOMP_SIZE_ASSERT(LegoAnimNodeData, 0x34)
DECOMP_SIZE_ASSERT(LegoAnimActorEntry, 0x08)
DECOMP_SIZE_ASSERT(LegoAnimScene, 0x24)
DECOMP_SIZE_ASSERT(LegoAnim, 0x18)

// FUNCTION: LEGO1 0x1009f000
LegoUnknownKey::LegoUnknownKey()
{
	m_unk0x08 = 0;
}

// FUNCTION: LEGO1 0x1009f020
LegoResult LegoUnknownKey::Read(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Read(p_storage)) != SUCCESS) {
		return result;
	}

	result = p_storage->Read(&m_unk0x08, sizeof(m_unk0x08));
	return result == SUCCESS ? SUCCESS : result;
}

// FUNCTION: LEGO1 0x1009f0a0
LegoAnimScene::LegoAnimScene()
{
	m_unk0x00 = 0;
	m_unk0x04 = NULL;
	m_unk0x08 = 0;
	m_unk0x0c = NULL;
	m_unk0x10 = 0;
	m_unk0x14 = NULL;
	m_unk0x18 = 0;
	m_unk0x1c = 0;
	m_unk0x20 = 0;
}

// FUNCTION: LEGO1 0x1009f0d0
LegoAnimScene::~LegoAnimScene()
{
	if (m_unk0x04 != NULL) {
		delete[] m_unk0x04;
		m_unk0x04 = NULL;
	}

	if (m_unk0x0c != NULL) {
		delete[] m_unk0x0c;
		m_unk0x0c = NULL;
	}

	if (m_unk0x14 != NULL) {
		delete[] m_unk0x14;
		m_unk0x14 = NULL;
	}
}

// FUNCTION: LEGO1 0x1009f200
LegoResult LegoAnimScene::Read(LegoStorage* p_storage)
{
	LegoResult result;
	LegoS32 i;

	if ((result = p_storage->Read(&m_unk0x00, sizeof(m_unk0x00))) != SUCCESS) {
		return result;
	}

	if (m_unk0x00) {
		m_unk0x04 = new LegoTranslationKey[m_unk0x00];
		for (i = 0; i < m_unk0x00; i++) {
			if ((result = m_unk0x04[i].Read(p_storage)) != SUCCESS) {
				goto done;
			}
		}
	}

	if ((result = p_storage->Read(&m_unk0x08, sizeof(m_unk0x08))) != SUCCESS) {
		return result;
	}

	if (m_unk0x08) {
		m_unk0x0c = new LegoTranslationKey[m_unk0x08];
		for (i = 0; i < m_unk0x08; i++) {
			if ((result = m_unk0x0c[i].Read(p_storage)) != SUCCESS) {
				goto done;
			}
		}
	}

	if ((result = p_storage->Read(&m_unk0x10, sizeof(m_unk0x10))) != SUCCESS) {
		return result;
	}

	if (m_unk0x10) {
		m_unk0x14 = new LegoUnknownKey[m_unk0x10];
		for (i = 0; i < m_unk0x10; i++) {
			if ((result = m_unk0x14[i].Read(p_storage)) != SUCCESS) {
				goto done;
			}
		}
	}

	return SUCCESS;

done:
	if (m_unk0x04 != NULL) {
		delete[] m_unk0x04;
		m_unk0x00 = 0;
		m_unk0x04 = NULL;
	}

	if (m_unk0x0c != NULL) {
		delete[] m_unk0x0c;
		m_unk0x08 = 0;
		m_unk0x0c = NULL;
	}

	if (m_unk0x14 != NULL) {
		delete[] m_unk0x14;
		m_unk0x10 = 0;
		m_unk0x14 = NULL;
	}

	return result;
}

// STUB: LEGO1 0x1009f490
undefined4 LegoAnimScene::FUN_1009f490(LegoFloat p_time, Matrix4& p_matrix)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x1009f900
LegoAnimKey::LegoAnimKey()
{
	m_flags = 0;
	m_time = 0;
}

// FUNCTION: LEGO1 0x1009f910
LegoResult LegoAnimKey::Read(LegoStorage* p_storage)
{
	LegoResult result;
	LegoS32 und;

	if ((result = p_storage->Read(&und, sizeof(und))) != SUCCESS) {
		return result;
	}

	m_flags = (LegoU32) und >> 24;
	m_time = und & 0xffffff;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009f990
LegoTranslationKey::LegoTranslationKey()
{
	m_x = 0.0F;
	m_y = 0.0F;
	m_z = 0.0F;
}

// FUNCTION: LEGO1 0x1009f9b0
LegoResult LegoTranslationKey::Read(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Read(p_storage)) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_x, sizeof(m_x))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_y, sizeof(m_y))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_z, sizeof(m_z))) != SUCCESS) {
		return result;
	}

	if (m_x > 1e-05F || m_x < -1e-05F || m_y > 1e-05F || m_y < -1e-05F || m_z > 1e-05F || m_z < -1e-05F) {
		m_flags |= c_bit1;
	}

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

// FUNCTION: LEGO1 0x1009fac0
LegoResult LegoRotationKey::Read(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Read(p_storage)) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_angle, sizeof(m_angle))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_x, sizeof(m_x))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_y, sizeof(m_y))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_z, sizeof(m_z))) != SUCCESS) {
		return result;
	}

	if (m_angle != 1.0F) {
		m_flags |= c_bit1;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009fba0
LegoScaleKey::LegoScaleKey()
{
	m_x = 1.0F;
	m_y = 1.0F;
	m_z = 1.0F;
}

// FUNCTION: LEGO1 0x1009fbc0
LegoResult LegoScaleKey::Read(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Read(p_storage)) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_x, sizeof(m_x))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_y, sizeof(m_y))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_z, sizeof(m_z))) != SUCCESS) {
		return result;
	}

	if (m_x > 1.00001 || m_x < 0.99999 || m_y > 1.00001 || m_y < 0.99999 || m_z > 1.00001 || m_z < 0.99999) {
		m_flags |= c_bit1;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009fcf0
LegoAnimNodeData::LegoAnimNodeData()
{
	m_numTranslationKeys = 0;
	m_numRotationKeys = 0;
	m_numScaleKeys = 0;
	m_numMorphKeys = 0;

	m_name = NULL;
	m_translationKeys = NULL;
	m_unk0x20 = 0;
	m_rotationKeys = NULL;
	m_unk0x22 = 0;
	m_scaleKeys = NULL;
	m_morphKeys = NULL;
	m_translationIndex = 0;
	m_rotationIndex = 0;
	m_scaleIndex = 0;
	m_morphIndex = 0;
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

// FUNCTION: LEGO1 0x100a03c0
LegoResult LegoAnimNodeData::CreateLocalTransform(LegoFloat p_time, Matrix4& p_matrix)
{
	LegoU32 index;

	if (m_scaleKeys != NULL) {
		index = GetScaleIndex();
		GetScale(m_numScaleKeys, m_scaleKeys, p_time, p_matrix, index);
		SetScaleIndex(index);

		if (m_rotationKeys != NULL) {
			MxMatrix a, b;
			a.SetIdentity();

			index = GetRotationIndex();
			GetRotation(m_numRotationKeys, m_rotationKeys, p_time, a, index);
			SetRotationIndex(index);

			b = p_matrix;
			p_matrix.Product(b, a);
		}
	}
	else if (m_rotationKeys != NULL) {
		index = GetRotationIndex();
		GetRotation(m_numRotationKeys, m_rotationKeys, p_time, p_matrix, index);
		SetRotationIndex(index);
	}

	if (m_translationKeys != NULL) {
		index = GetTranslationIndex();
		GetTranslation(m_numTranslationKeys, m_translationKeys, p_time, p_matrix, index);
		SetTranslationIndex(index);
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100a0600
inline void LegoAnimNodeData::GetTranslation(
	LegoU16 p_numTranslationKeys,
	LegoTranslationKey* p_translationKeys,
	LegoFloat p_time,
	Matrix4& p_matrix,
	LegoU32& p_old_index
)
{
	LegoU32 i, n;
	LegoFloat x, y, z;
	n = FindKeys(
		p_time,
		p_numTranslationKeys & USHRT_MAX,
		p_translationKeys,
		sizeof(*p_translationKeys),
		i,
		p_old_index
	);

	switch (n) {
	case 0:
		return;
	case 1:
		if (!p_translationKeys[i].TestBit1()) {
			return;
		}

		x = p_translationKeys[i].GetX();
		y = p_translationKeys[i].GetY();
		z = p_translationKeys[i].GetZ();
		break;
	case 2:
		if (!p_translationKeys[i].TestBit1() && !p_translationKeys[i + 1].TestBit1()) {
			return;
		}

		x = Interpolate(
			p_time,
			p_translationKeys[i],
			p_translationKeys[i].GetX(),
			p_translationKeys[i + 1],
			p_translationKeys[i + 1].GetX()
		);
		y = Interpolate(
			p_time,
			p_translationKeys[i],
			p_translationKeys[i].GetY(),
			p_translationKeys[i + 1],
			p_translationKeys[i + 1].GetY()
		);
		z = Interpolate(
			p_time,
			p_translationKeys[i],
			p_translationKeys[i].GetZ(),
			p_translationKeys[i + 1],
			p_translationKeys[i + 1].GetZ()
		);
		break;
	}

	p_matrix.TranslateBy(&x, &y, &z);
}

// FUNCTION: LEGO1 0x100a06f0
/*inline*/ void LegoAnimNodeData::GetRotation(
	LegoU16 p_numRotationKeys,
	LegoRotationKey* p_rotationKeys,
	LegoFloat p_time,
	Matrix4& p_matrix,
	LegoU32& p_old_index
)
{
	LegoU32 i, n;
	n = FindKeys(p_time, p_numRotationKeys & USHRT_MAX, p_rotationKeys, sizeof(*p_rotationKeys), i, p_old_index);

	switch (n) {
	case 0:
		return;
	case 1:
		if (p_rotationKeys[i].TestBit1()) {
			p_matrix.FromQuaternion(Mx4DPointFloat(
				p_rotationKeys[i].GetX(),
				p_rotationKeys[i].GetY(),
				p_rotationKeys[i].GetZ(),
				p_rotationKeys[i].GetAngle()
			));
		}
		break;
	case 2:
		Mx4DPointFloat a;
		UnknownMx4DPointFloat b;

		if (p_rotationKeys[i].TestBit1() || p_rotationKeys[i + 1].TestBit1()) {
			a[0] = p_rotationKeys[i].GetX();
			a[1] = p_rotationKeys[i].GetY();
			a[2] = p_rotationKeys[i].GetZ();
			a[3] = p_rotationKeys[i].GetAngle();

			if (p_rotationKeys[i + 1].TestBit3()) {
				p_matrix.FromQuaternion(a);
				return;
			}

			Mx4DPointFloat c;
			if (p_rotationKeys[i + 1].TestBit2()) {
				c[0] = -p_rotationKeys[i + 1].GetX();
				c[1] = -p_rotationKeys[i + 1].GetY();
				c[2] = -p_rotationKeys[i + 1].GetZ();
				c[3] = -p_rotationKeys[i + 1].GetAngle();
			}
			else {
				c[0] = p_rotationKeys[i + 1].GetX();
				c[1] = p_rotationKeys[i + 1].GetY();
				c[2] = p_rotationKeys[i + 1].GetZ();
				c[3] = p_rotationKeys[i + 1].GetAngle();
			}

			b.Unknown1(a);
			b.Unknown2(c);
			b.Unknown_100040a0(
				p_matrix,
				(p_time - p_rotationKeys[i].GetTime()) / (p_rotationKeys[i + 1].GetTime() - p_rotationKeys[i].GetTime())
			);
		}
	}
}

inline void LegoAnimNodeData::GetScale(
	LegoU16 p_numScaleKeys,
	LegoScaleKey* p_scaleKeys,
	LegoFloat p_time,
	Matrix4& p_matrix,
	LegoU32& p_old_index
)
{
	LegoU32 i, n;
	LegoFloat x, y, z;
	n = FindKeys(p_time, p_numScaleKeys & USHRT_MAX, p_scaleKeys, sizeof(*p_scaleKeys), i, p_old_index);

	switch (n) {
	case 0:
		return;
	case 1:
		x = p_scaleKeys[i].GetX();
		y = p_scaleKeys[i].GetY();
		z = p_scaleKeys[i].GetZ();
		break;
	case 2:
		x = Interpolate(p_time, p_scaleKeys[i], p_scaleKeys[i].GetX(), p_scaleKeys[i + 1], p_scaleKeys[i + 1].GetX());
		y = Interpolate(p_time, p_scaleKeys[i], p_scaleKeys[i].GetY(), p_scaleKeys[i + 1], p_scaleKeys[i + 1].GetY());
		z = Interpolate(p_time, p_scaleKeys[i], p_scaleKeys[i].GetZ(), p_scaleKeys[i + 1], p_scaleKeys[i + 1].GetZ());
		break;
	}

	p_matrix.Scale(x, y, z);
}

// FUNCTION: LEGO1 0x100a0990
LegoBool LegoAnimNodeData::FUN_100a0990(LegoFloat p_time)
{
	LegoU32 i, n;
	LegoU32 index = GetMorphIndex();
	LegoBool result;

	n = FindKeys(p_time, m_numMorphKeys, m_morphKeys, sizeof(*m_morphKeys), i, index);
	SetMorphIndex(index);

	switch (n) {
	case 0:
		result = TRUE;
		break;
	case 1:
	case 2:
		result = m_morphKeys[i].GetUnknown0x08();
		break;
	}

	return result;
}

// STUB: LEGO1 0x100a0a00
LegoU32 LegoAnimNodeData::FindKeys(
	LegoFloat p_time,
	LegoU32 p_numKeys,
	LegoAnimKey* p_keys,
	LegoU32 p_size,
	LegoU32& p_new_index,
	LegoU32& p_old_index
)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x100a0b00
inline LegoFloat LegoAnimNodeData::Interpolate(
	LegoFloat p_time,
	LegoAnimKey& p_key1,
	LegoFloat p_value1,
	LegoAnimKey& p_key2,
	LegoFloat p_value2
)
{
	return p_value1 + (p_value2 - p_value1) * (p_time - p_key1.GetTime()) / (p_key2.GetTime() - p_key1.GetTime());
}

// FUNCTION: LEGO1 0x100a0b30
LegoAnim::LegoAnim()
{
	m_duration = 0;
	m_actors = NULL;
	m_numActors = 0;
	m_scene = NULL;
}

// FUNCTION: LEGO1 0x100a0bc0
LegoAnim::~LegoAnim()
{
	if (m_actors != NULL) {
		for (LegoU32 i = 0; i < m_numActors; i++) {
			delete[] m_actors[i].m_name;
		}

		delete[] m_actors;
	}

	if (m_scene != NULL) {
		delete m_scene;
	}
}

// FUNCTION: LEGO1 0x100a0c70
LegoResult LegoAnim::Read(LegoStorage* p_storage, LegoS32 p_parseScene)
{
	LegoResult result = FAILURE;
	LegoU32 length, i;

	if (p_storage->Read(&length, sizeof(length)) != SUCCESS) {
		goto done;
	}

	m_actors = new LegoAnimActorEntry[length];
	m_numActors = 0;

	for (i = 0; i < length; i++) {
		LegoU32 length;
		if (p_storage->Read(&length, sizeof(length)) != SUCCESS) {
			goto done;
		}

		if (length) {
			m_actors[i].m_name = new LegoChar[length + 1];

			if (p_storage->Read(m_actors[i].m_name, length) != SUCCESS) {
				goto done;
			}

			m_actors[i].m_name[length] = '\0';

			if (p_storage->Read(&m_actors[i].m_unk0x04, sizeof(m_actors[i].m_unk0x04)) != SUCCESS) {
				goto done;
			}
		}

		m_numActors++;
	}

	if ((result = p_storage->Read(&m_duration, sizeof(m_duration))) != SUCCESS) {
		goto done;
	}

	if (p_parseScene) {
		m_scene = new LegoAnimScene();

		result = m_scene->Read(p_storage);

		if (result != SUCCESS) {
			goto done;
		}
	}

	result = LegoTree::Read(p_storage);

done:
	if (result != SUCCESS && m_actors != NULL) {
		for (i = 0; i < m_numActors; i++) {
			delete[] m_actors[i].m_name;
		}

		m_numActors = 0;
		delete[] m_actors;
		m_actors = NULL;
	}

	return result;
}

// STUB: LEGO1 0x100a0e30
LegoResult LegoAnim::Write(LegoStorage* p_storage)
{
	// TODO
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100a0f20
const LegoChar* LegoAnim::GetActorName(LegoU32 p_index)
{
	if (p_index < m_numActors) {
		return m_actors[p_index].m_name;
	}

	return NULL;
}

// FUNCTION: LEGO1 0x100a0f40
undefined4 LegoAnim::GetActorUnknown0x04(LegoU32 p_index)
{
	if (p_index < m_numActors) {
		return m_actors[p_index].m_unk0x04;
	}

	return NULL;
}

// FUNCTION: LEGO1 0x100a0f60
LegoMorphKey::LegoMorphKey()
{
	m_unk0x08 = 0;
}

// FUNCTION: LEGO1 0x100a0f70
LegoResult LegoMorphKey::Read(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Read(p_storage)) != SUCCESS) {
		return result;
	}

	result = p_storage->Read(&m_unk0x08, sizeof(m_unk0x08));
	return result == SUCCESS ? SUCCESS : result;
}
