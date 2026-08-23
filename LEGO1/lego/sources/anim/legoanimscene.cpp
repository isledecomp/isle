// The order of these includes is byte-identity significant: it decides which
// of Tgl::Constant::Pi and rotateIndex[] this unit seats first in its .rdata
// constant pool, and clang-format would sort them back.
// clang-format off
#include "legoanim.h"
// clang-format on

// GLOBAL: LEGO1 0x100db830
// Retail seats this constant ahead of Tgl::Constant::Pi in the unit's .rdata
// pool.  MSVC 4.2 orders a pool by internal symbol number and numbers named
// file-scope statics at parse time, ahead of every function-body literal, so it
// can only be a named const declared before tgl/tglvector.h is parsed -- no
// expression inside a function can produce it there.  Nothing in the retail
// image reads it and BETA10 does not carry it at all, so the 1997 declaration
// that named it is not recoverable; the helper below exists only to keep the
// constant emitted, and is never called, so no code of it reaches the image.
static const double g_unk0x100db830 = 0.5;

inline double UnkGet0x100db830()
{
	return g_unk0x100db830;
}

// clang-format off
#include "tgl/tglvector.h"
#include "mxgeometry/mxmatrix.h"
#include "mxgeometry/mxquaternion.h"

#include <assert.h>
#include <limits.h>
// clang-format on

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
// FUNCTION: BETA10 0x101813a3
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
// FUNCTION: BETA10 0x10181412
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
// FUNCTION: BETA10 0x1018167e
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
