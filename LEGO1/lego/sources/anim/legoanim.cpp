#include "legoanim.h"

#include "mxgeometry/mxmatrix.h"
#include "mxgeometry/mxquaternion.h"

#include <limits.h>

DECOMP_SIZE_ASSERT(LegoAnimKey, 0x08)
DECOMP_SIZE_ASSERT(LegoTranslationKey, 0x14)
DECOMP_SIZE_ASSERT(LegoRotationKey, 0x18)
DECOMP_SIZE_ASSERT(LegoScaleKey, 0x14)
DECOMP_SIZE_ASSERT(LegoMorphKey, 0x0c)
DECOMP_SIZE_ASSERT(LegoRotationZKey, 0x0c)
DECOMP_SIZE_ASSERT(LegoAnimNodeData, 0x34)
DECOMP_SIZE_ASSERT(LegoAnimActorEntry, 0x08)
DECOMP_SIZE_ASSERT(LegoAnimScene, 0x24)
DECOMP_SIZE_ASSERT(LegoAnim, 0x18)

// FUNCTION: LEGO1 0x1009f000
LegoRotationZKey::LegoRotationZKey()
{
	m_z = 0.0f;
}

// FUNCTION: LEGO1 0x1009f020
LegoResult LegoRotationZKey::Read(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Read(p_storage)) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_z, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009f060
// FUNCTION: BETA10 0x1018133f
LegoResult LegoRotationZKey::Write(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Write(p_storage)) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_z, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009f0a0
LegoAnimScene::LegoAnimScene()
{
	m_translationKeysCount = 0;
	m_translationKeys = NULL;
	m_targetKeysCount = 0;
	m_targetKeys = NULL;
	m_rotationKeysCount = 0;
	m_rotationKeys = NULL;
	m_targetIndex = 0;
	m_translationIndex = 0;
	m_rotationIndex = 0;
}

// FUNCTION: LEGO1 0x1009f0d0
LegoAnimScene::~LegoAnimScene()
{
	if (m_translationKeys != NULL) {
		delete[] m_translationKeys;
		m_translationKeys = NULL;
	}

	if (m_targetKeys != NULL) {
		delete[] m_targetKeys;
		m_targetKeys = NULL;
	}

	if (m_rotationKeys != NULL) {
		delete[] m_rotationKeys;
		m_rotationKeys = NULL;
	}
}

// FUNCTION: LEGO1 0x1009f120
// FUNCTION: BETA10 0x101814be
LegoResult LegoAnimScene::Write(LegoStorage* p_storage)
{
	LegoResult result;
	LegoS32 i;

	if ((result = p_storage->Write(&m_translationKeysCount, sizeof(LegoU16))) != SUCCESS) {
		return result;
	}
	if (m_translationKeysCount != 0) {
		for (i = 0; i < m_translationKeysCount; i++) {
			if ((result = m_translationKeys[i].Write(p_storage)) != SUCCESS) {
				return result;
			}
		}
	}

	if ((result = p_storage->Write(&m_targetKeysCount, sizeof(LegoU16))) != SUCCESS) {
		return result;
	}
	if (m_targetKeysCount != 0) {
		for (i = 0; i < m_targetKeysCount; i++) {
			if ((result = m_targetKeys[i].Write(p_storage)) != SUCCESS) {
				return result;
			}
		}
	}

	if ((result = p_storage->Write(&m_rotationKeysCount, sizeof(LegoU16))) != SUCCESS) {
		return result;
	}
	if (m_rotationKeysCount != 0) {
		for (i = 0; i < m_rotationKeysCount; i++) {
			if ((result = m_rotationKeys[i].Write(p_storage)) != SUCCESS) {
				return result;
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009f200
LegoResult LegoAnimScene::Read(LegoStorage* p_storage)
{
	LegoResult result;
	LegoS32 i;

	if ((result = p_storage->Read(&m_translationKeysCount, sizeof(LegoU16))) != SUCCESS) {
		return result;
	}
	if (m_translationKeysCount != 0) {
		m_translationKeys = new LegoTranslationKey[m_translationKeysCount];
		for (i = 0; i < m_translationKeysCount; i++) {
			if ((result = m_translationKeys[i].Read(p_storage)) != SUCCESS) {
				goto done;
			}
		}
	}

	if ((result = p_storage->Read(&m_targetKeysCount, sizeof(LegoU16))) != SUCCESS) {
		return result;
	}
	if (m_targetKeysCount != 0) {
		m_targetKeys = new LegoTranslationKey[m_targetKeysCount];
		for (i = 0; i < m_targetKeysCount; i++) {
			if ((result = m_targetKeys[i].Read(p_storage)) != SUCCESS) {
				goto done;
			}
		}
	}

	if ((result = p_storage->Read(&m_rotationKeysCount, sizeof(LegoU16))) != SUCCESS) {
		return result;
	}
	if (m_rotationKeysCount != 0) {
		m_rotationKeys = new LegoRotationZKey[m_rotationKeysCount];
		for (i = 0; i < m_rotationKeysCount; i++) {
			if ((result = m_rotationKeys[i].Read(p_storage)) != SUCCESS) {
				goto done;
			}
		}
	}

	return SUCCESS;

done:
	if (m_translationKeys != NULL) {
		delete[] m_translationKeys;
		m_translationKeysCount = 0;
		m_translationKeys = NULL;
	}

	if (m_targetKeys != NULL) {
		delete[] m_targetKeys;
		m_targetKeysCount = 0;
		m_targetKeys = NULL;
	}

	if (m_rotationKeys != NULL) {
		delete[] m_rotationKeys;
		m_rotationKeysCount = 0;
		m_rotationKeys = NULL;
	}

	return result;
}

// FUNCTION: LEGO1 0x1009f490
// FUNCTION: BETA10 0x10181a83
LegoResult LegoAnimScene::CalculateCameraTransform(LegoFloat p_time, Matrix4& p_matrix)
{
	MxMatrix tempMatrix;
	MxMatrix original;

	Vector3 column0(tempMatrix[0]);
	Vector3 column1(tempMatrix[1]);
	Vector3 column2(tempMatrix[2]);
	Vector3 column3(tempMatrix[3]);

	Mx3DPointFloat tempTranslation;

	tempMatrix.SetIdentity();

	LegoU32 translationIndex;
	if (m_targetKeysCount != 0) {
		translationIndex = GetTargetIndex();
		LegoAnimNodeData::GetTranslation(m_targetKeysCount, m_targetKeys, p_time, tempMatrix, translationIndex);
		SetTargetIndex(translationIndex);
		tempTranslation = column3;
		column3.Clear();
	}

	if (m_translationKeysCount != 0) {
		translationIndex = GetTranslationIndex();
		LegoAnimNodeData::GetTranslation(
			m_translationKeysCount,
			m_translationKeys,
			p_time,
			tempMatrix,
			translationIndex
		);
		SetTranslationIndex(translationIndex);
	}

	column2 = tempTranslation;
	column2 -= column3;

	if (column2.Unitize() == 0) {
		column0.EqualsCross(column1, column2);

		if (column0.Unitize() == 0) {
			column1.EqualsCross(column2, column0);

			tempTranslation = p_matrix[3];
			tempTranslation += tempMatrix[3];

			p_matrix[3][0] = p_matrix[3][1] = p_matrix[3][2] = tempMatrix[3][0] = tempMatrix[3][1] = tempMatrix[3][2] =
				0;

			if (m_rotationKeysCount != 0) {
				LegoU32 old_index = -1;
				LegoU32 i;
				old_index = GetRotationIndex();

				LegoU32 count = LegoAnimNodeData::FindKeys(
					p_time,
					m_rotationKeysCount,
					m_rotationKeys,
					sizeof(*m_rotationKeys),
					i,
					old_index
				);

				SetRotationIndex(old_index);

				switch (count) {
				case 1:
					p_matrix.RotateZ(m_rotationKeys[i].GetZ());
					break;
				case 2:
					// Seems to be unused
					LegoFloat z = LegoAnimNodeData::Interpolate(
						p_time,
						m_rotationKeys[i],
						m_rotationKeys[i].GetZ(),
						m_rotationKeys[i + 1],
						m_rotationKeys[i + 1].GetZ()
					);
					p_matrix.RotateZ(m_rotationKeys[i].GetZ());
					break;
				}
			}

			original = p_matrix;
			p_matrix.Product(original.GetData(), tempMatrix.GetData());
			p_matrix[3][0] = tempTranslation[0];
			p_matrix[3][1] = tempTranslation[1];
			p_matrix[3][2] = tempTranslation[2];
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009f900
// FUNCTION: BETA10 0x1017df90
LegoAnimKey::LegoAnimKey()
{
	m_time = 0;
	m_flags = 0;
}

// FUNCTION: LEGO1 0x1009f910
LegoResult LegoAnimKey::Read(LegoStorage* p_storage)
{
	LegoResult result;
	LegoS32 timeAndFlags;

	if ((result = p_storage->Read(&timeAndFlags, sizeof(LegoS32))) != SUCCESS) {
		return result;
	}

	m_flags = (LegoU32) timeAndFlags >> 24;
	m_time = timeAndFlags & 0xffffff;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009f950
// FUNCTION: BETA10 0x1017e018
LegoResult LegoAnimKey::Write(LegoStorage* p_storage)
{
	LegoResult result;
	LegoS32 timeAndFlags = (LegoS32) m_time | (m_flags << 24);

	if ((result = p_storage->Write(&timeAndFlags, sizeof(LegoS32))) != SUCCESS) {
		return result;
	}

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

	if ((result = p_storage->Read(&m_x, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_y, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_z, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if (m_x > 1e-05F || m_x < -1e-05F || m_y > 1e-05F || m_y < -1e-05F || m_z > 1e-05F || m_z < -1e-05F) {
		m_flags |= c_active;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009fa40
// FUNCTION: BETA10 0x1017e1fd
LegoResult LegoTranslationKey::Write(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Write(p_storage)) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_x, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_y, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_z, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009faa0
// FUNCTION: BETA10 0x1017e2b3
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

	if ((result = p_storage->Read(&m_angle, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_x, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_y, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_z, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if (m_angle != 1.0F) {
		m_flags |= c_active;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009fb30
// FUNCTION: BETA10 0x1017e3fc
LegoResult LegoRotationKey::Write(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Write(p_storage)) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_angle, sizeof(m_angle))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_x, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_y, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_z, sizeof(LegoFloat))) != SUCCESS) {
		return result;
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

	if ((result = p_storage->Read(&m_x, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_y, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_z, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if (m_x > 1.00001 || m_x < 0.99999 || m_y > 1.00001 || m_y < 0.99999 || m_z > 1.00001 || m_z < 0.99999) {
		m_flags |= c_active;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009fc90
// FUNCTION: BETA10 0x1017e664
LegoResult LegoScaleKey::Write(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Write(p_storage)) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_x, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_y, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_z, sizeof(LegoFloat))) != SUCCESS) {
		return result;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1009fcf0
// FUNCTION: BETA10 0x1017e71a
LegoAnimNodeData::LegoAnimNodeData()
{
	m_numTranslationKeys = 0;
	m_numRotationKeys = 0;
	m_numScaleKeys = 0;
	m_numMorphKeys = 0;

	m_name = NULL;
	m_translationKeys = NULL;
	m_roiIndex = 0;
	m_rotationKeys = NULL;
	m_boundaryIndex = 0;
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
// FUNCTION: BETA10 0x1017e949
LegoResult LegoAnimNodeData::Read(LegoStorage* p_storage)
{
	LegoResult result;

	LegoU32 length;
	if ((result = p_storage->Read(&length, sizeof(LegoU32))) != SUCCESS) {
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

	if ((result = p_storage->Read(&m_numTranslationKeys, sizeof(LegoU16))) != SUCCESS) {
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

	if ((result = p_storage->Read(&m_numRotationKeys, sizeof(LegoU16))) != SUCCESS) {
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

	if ((result = p_storage->Read(&m_numScaleKeys, sizeof(LegoU16))) != SUCCESS) {
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

	if ((result = p_storage->Read(&m_numMorphKeys, sizeof(LegoU16))) != SUCCESS) {
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

// FUNCTION: LEGO1 0x100a01e0
// FUNCTION: BETA10 0x1017ef0f
LegoResult LegoAnimNodeData::Write(LegoStorage* p_storage)
{
	LegoResult result;
	LegoU32 length = 0;
	LegoU32 i;

	if (m_name != NULL) {
		length = strlen(m_name);
	}

	if ((result = p_storage->Write(&length, sizeof(length))) != SUCCESS) {
		return result;
	}

	if (m_name != NULL && (result = p_storage->Write(m_name, length)) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_numTranslationKeys, sizeof(LegoU16))) != SUCCESS) {
		return result;
	}
	if (m_numTranslationKeys != 0) {
		for (i = 0; i < m_numTranslationKeys; i++) {
			if ((result = m_translationKeys[i].Write(p_storage)) != SUCCESS) {
				return result;
			}
		}
	}

	if ((result = p_storage->Write(&m_numRotationKeys, sizeof(LegoU16))) != SUCCESS) {
		return result;
	}
	if (m_numRotationKeys != 0) {
		for (i = 0; i < m_numRotationKeys; i++) {
			if ((result = m_rotationKeys[i].Write(p_storage)) != SUCCESS) {
				return result;
			}
		}
	}

	if ((result = p_storage->Write(&m_numScaleKeys, sizeof(LegoU16))) != SUCCESS) {
		return result;
	}
	if (m_numScaleKeys != 0) {
		for (i = 0; i < m_numScaleKeys; i++) {
			if ((result = m_scaleKeys[i].Write(p_storage)) != SUCCESS) {
				return result;
			}
		}
	}

	if ((result = p_storage->Write(&m_numMorphKeys, sizeof(LegoU16))) != SUCCESS) {
		return result;
	}
	if (m_numMorphKeys != 0) {
		for (i = 0; i < m_numMorphKeys; i++) {
			if ((result = m_morphKeys[i].Write(p_storage)) != SUCCESS) {
				return result;
			}
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100a0360
// FUNCTION: BETA10 0x1017f1e5
void LegoAnimNodeData::SetName(LegoChar* p_name)
{
	if (m_name != NULL) {
		delete[] m_name;
	}

	m_name = new LegoChar[strlen(p_name) + 1];
	strcpy(m_name, p_name);
}

// FUNCTION: LEGO1 0x100a03c0
// FUNCTION: BETA10 0x1017f254
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
		if (!p_translationKeys[i].IsActive()) {
			return;
		}

		x = p_translationKeys[i].GetX();
		y = p_translationKeys[i].GetY();
		z = p_translationKeys[i].GetZ();
		break;
	case 2:
		if (!p_translationKeys[i].IsActive() && !p_translationKeys[i + 1].IsActive()) {
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

	p_matrix.TranslateBy(x, y, z);
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
		if (p_rotationKeys[i].IsActive()) {
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
		MxQuaternionTransformer b;

		if (p_rotationKeys[i].IsActive() || p_rotationKeys[i + 1].IsActive()) {
			a[0] = p_rotationKeys[i].GetX();
			a[1] = p_rotationKeys[i].GetY();
			a[2] = p_rotationKeys[i].GetZ();
			a[3] = p_rotationKeys[i].GetAngle();

			if (p_rotationKeys[i + 1].ShouldSkipInterpolation()) {
				p_matrix.FromQuaternion(a);
				return;
			}

			Mx4DPointFloat c;
			if (p_rotationKeys[i + 1].ShouldNegateRotation()) {
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

			b.SetStart(a);
			b.SetEnd(c);
			b.InterpolateToMatrix(
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
LegoBool LegoAnimNodeData::GetVisibility(LegoFloat p_time)
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
		result = m_morphKeys[i].IsVisible();
		break;
	}

	return result;
}

// FUNCTION: LEGO1 0x100a0a00
LegoU32 LegoAnimNodeData::FindKeys(
	LegoFloat p_time,
	LegoU32 p_numKeys,
	LegoAnimKey* p_keys,
	LegoU32 p_size,
	LegoU32& p_new_index,
	LegoU32& p_old_index
)
{
	LegoU32 numKeys;
	if (p_numKeys == 0) {
		numKeys = 0;
	}
	else if (p_time < GetKey(0, p_keys, p_size).GetTime()) {
		numKeys = 0;
	}
	else if (p_time > GetKey(p_numKeys - 1, p_keys, p_size).GetTime()) {
		p_new_index = p_numKeys - 1;
		numKeys = 1;
	}
	else {
		if (GetKey(p_old_index, p_keys, p_size).GetTime() <= p_time) {
			for (p_new_index = p_old_index;
				 p_new_index < p_numKeys - 1 && p_time >= GetKey(p_new_index + 1, p_keys, p_size).GetTime();
				 p_new_index++) {
			}
		}
		else {
			for (p_new_index = 0;
				 p_new_index < p_numKeys - 1 && p_time >= GetKey(p_new_index + 1, p_keys, p_size).GetTime();
				 p_new_index++) {
			}
		}

		p_old_index = p_new_index;
		if (p_time == GetKey(p_new_index, p_keys, p_size).GetTime()) {
			numKeys = 1;
		}
		else if (p_new_index < p_numKeys - 1) {
			numKeys = 2;
		}
		else {
			numKeys = 0;
		}
	}

	return numKeys;
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

inline LegoAnimKey& LegoAnimNodeData::GetKey(LegoU32 p_i, LegoAnimKey* p_keys, LegoU32 p_size)
{
	return *((LegoAnimKey*) (((LegoU8*) p_keys) + (p_i * p_size)));
}

// FUNCTION: LEGO1 0x100a0b30
LegoAnim::LegoAnim()
{
	m_duration = 0;
	m_modelList = NULL;
	m_numActors = 0;
	m_camAnim = NULL;
}

// FUNCTION: LEGO1 0x100a0bc0
LegoAnim::~LegoAnim()
{
	if (m_modelList != NULL) {
		for (LegoU32 i = 0; i < m_numActors; i++) {
			delete[] m_modelList[i].m_name;
		}

		delete[] m_modelList;
	}

	if (m_camAnim != NULL) {
		delete m_camAnim;
	}
}

// FUNCTION: LEGO1 0x100a0c70
LegoResult LegoAnim::Read(LegoStorage* p_storage, LegoS32 p_parseScene)
{
	LegoResult result = FAILURE;
	LegoU32 length, i;

	if (p_storage->Read(&length, sizeof(LegoU32)) != SUCCESS) {
		goto done;
	}

	m_modelList = new LegoAnimActorEntry[length];
	m_numActors = 0;

	for (i = 0; i < length; i++) {
		LegoU32 length;
		if (p_storage->Read(&length, sizeof(LegoU32)) != SUCCESS) {
			goto done;
		}

		if (length) {
			m_modelList[i].m_name = new LegoChar[length + 1];

			if (p_storage->Read(m_modelList[i].m_name, length) != SUCCESS) {
				goto done;
			}

			m_modelList[i].m_name[length] = '\0';

			if (p_storage->Read(&m_modelList[i].m_type, sizeof(LegoU32)) != SUCCESS) {
				goto done;
			}
		}

		m_numActors++;
	}

	if ((result = p_storage->Read(&m_duration, sizeof(LegoS32))) != SUCCESS) {
		goto done;
	}

	if (p_parseScene) {
		m_camAnim = new LegoAnimScene();

		result = m_camAnim->Read(p_storage);

		if (result != SUCCESS) {
			goto done;
		}
	}

	result = LegoTree::Read(p_storage);

done:
	if (result != SUCCESS && m_modelList != NULL) {
		for (i = 0; i < m_numActors; i++) {
			delete[] m_modelList[i].m_name;
		}

		m_numActors = 0;
		delete[] m_modelList;
		m_modelList = NULL;
	}

	return result;
}

// FUNCTION: LEGO1 0x100a0e30
// FUNCTION: BETA10 0x1017fe3a
LegoResult LegoAnim::Write(LegoStorage* p_storage)
{
	LegoResult result = FAILURE;
	LegoU32 i;

	if (p_storage->Write(&m_numActors, sizeof(m_numActors)) != SUCCESS) {
		goto done;
	}

	for (i = 0; i < m_numActors; i++) {
		LegoU32 length = strlen(m_modelList[i].m_name);

		if (p_storage->Write(&length, sizeof(length)) != SUCCESS) {
			goto done;
		}

		if (length != 0) {
			if (p_storage->Write(m_modelList[i].m_name, length) != SUCCESS) {
				goto done;
			}

			if (p_storage->Write(&m_modelList[i].m_type, sizeof(m_modelList[i].m_type)) != SUCCESS) {
				goto done;
			}
		}
	}

	if (p_storage->Write(&m_duration, sizeof(m_duration)) != SUCCESS) {
		goto done;
	}

	if (m_camAnim != NULL) {
		if (m_camAnim->Write(p_storage) != SUCCESS) {
			goto done;
		}
	}

	result = LegoTree::Write(p_storage);

done:
	return result;
}

// FUNCTION: LEGO1 0x100a0f20
// FUNCTION: BETA10 0x101801fd
const LegoChar* LegoAnim::GetActorName(LegoU32 p_index)
{
	if (p_index < m_numActors) {
		return m_modelList[p_index].m_name;
	}

	return NULL;
}

// FUNCTION: LEGO1 0x100a0f40
// FUNCTION: BETA10 0x1018023c
LegoU32 LegoAnim::GetActorType(LegoU32 p_index)
{
	if (p_index < m_numActors) {
		return m_modelList[p_index].m_type;
	}

	return 0;
}

// FUNCTION: LEGO1 0x100a0f60
// FUNCTION: BETA10 0x1018027c
LegoMorphKey::LegoMorphKey()
{
	m_visible = FALSE;
}

// FUNCTION: LEGO1 0x100a0f70
LegoResult LegoMorphKey::Read(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Read(p_storage)) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Read(&m_visible, sizeof(LegoU8))) != SUCCESS) {
		return result;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100a0fb0
// FUNCTION: BETA10 0x10180308
LegoResult LegoMorphKey::Write(LegoStorage* p_storage)
{
	LegoResult result;

	if ((result = LegoAnimKey::Write(p_storage)) != SUCCESS) {
		return result;
	}

	if ((result = p_storage->Write(&m_visible, sizeof(LegoU8))) != SUCCESS) {
		return result;
	}

	return SUCCESS;
}
