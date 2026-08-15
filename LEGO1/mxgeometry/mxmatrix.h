#ifndef MXMATRIX_H
#define MXMATRIX_H

#include "realtime/matrix4d.inl.h"

// VTABLE: LEGO1 0x100d4300
// VTABLE: BETA10 0x101b82e0
// SIZE 0x48
class MxMatrix : public Matrix4 {
public:
	inline MxMatrix();

	inline MxMatrix(const MxMatrix& p_matrix);

	inline MxMatrix(const Matrix4& p_matrix);

	inline float* operator[](int idx);

	inline const float* operator[](int idx) const;

	inline void operator=(const Matrix4& p_matrix) override; // vtable+0x28

	inline virtual void operator=(const MxMatrix& p_matrix); // vtable+0x48

private:
	float m_elements[4][4]; // 0x08
};

// FUNCTION: LEGO1 0x1006b120
// FUNCTION: BETA10 0x10015370
MxMatrix::MxMatrix() : Matrix4(m_elements)
{
}

// FUNCTION: LEGO1 0x10032770
// FUNCTION: BETA10 0x1001ff30
MxMatrix::MxMatrix(const MxMatrix& p_matrix) : Matrix4(m_elements)
{
	CopyFrom(p_matrix);
}

// FUNCTION: BETA10 0x1000fc20
MxMatrix::MxMatrix(const Matrix4& p_matrix) : Matrix4(m_elements)
{
	CopyFrom(p_matrix);
}

// FUNCTION: LEGO1 0x10002850
// FUNCTION: BETA10 0x10010800
void MxMatrix::operator=(const Matrix4& p_matrix)
{
	CopyFrom(p_matrix);
}

// FUNCTION: LEGO1 0x10002860
// FUNCTION: BETA10 0x10010830
void MxMatrix::operator=(const MxMatrix& p_matrix)
{
	CopyFrom(p_matrix);
}

// FUNCTION: BETA10 0x10010860
float* MxMatrix::operator[](int idx)
{
	return m_data[idx];
}

const float* MxMatrix::operator[](int idx) const
{
	return m_data[idx];
}

// The non-virtual Matrix4 members are defined after the MxMatrix class.
// BETA10 emission order attests this placement: RotateX (0x1001c6a0) directly
// follows Matrix4::operator[] (0x1001c670), and RotateY/Scale (0x1001fd60,
// 0x1001fe60) precede MxMatrix(const MxMatrix&) (0x1001ff30).

// FUNCTION: BETA10 0x1001c6a0
void Matrix4::RotateX(const float& p_angle)
{
	float s = sin(p_angle);
	float c = cos(p_angle);
	float matrix[4][4];
	memcpy(matrix, m_data, sizeof(float) * 16);

	for (int i = 0; i < 4; i++) {
		m_data[i][1] = matrix[i][1] * c - matrix[i][2] * s;
		m_data[i][2] = matrix[i][2] * c + matrix[i][1] * s;
	}
}

// FUNCTION: BETA10 0x1001fd60
void Matrix4::RotateY(const float& p_angle)
{
	float s = sin(p_angle);
	float c = cos(p_angle);
	float matrix[4][4];
	memcpy(matrix, m_data, sizeof(float) * 16);

	for (int i = 0; i < 4; i++) {
		m_data[i][0] = matrix[i][0] * c + matrix[i][2] * s;
		m_data[i][2] = matrix[i][2] * c - matrix[i][0] * s;
	}
}

// FUNCTION: LEGO1 0x100a0ff0
// FUNCTION: BETA10 0x1001fe60
void Matrix4::Scale(const float& p_x, const float& p_y, const float& p_z)
{
	for (int i = 0; i < 4; i++) {
		m_data[i][0] *= p_x;
		m_data[i][1] *= p_y;
		m_data[i][2] *= p_z;
	}
}

// FUNCTION: BETA10 0x1006ab10
void Matrix4::RotateZ(const float& p_angle)
{
	float s = sin(p_angle);
	float c = cos(p_angle);
	float matrix[4][4];
	memcpy(matrix, m_data, sizeof(float) * 16);

	for (int i = 0; i < 4; i++) {
		m_data[i][0] = matrix[i][0] * c - matrix[i][1] * s;
		m_data[i][1] = matrix[i][1] * c + matrix[i][0] * s;
	}
}

// Must be included here (not before MxMatrix) for correct ordering in binary.
// FromQuaternion and ToQuaternion in Matrix4 depend on Vector4.
// There's a chance they included mxgeometry4d.h after including this somewhere.
#include "realtime/vector4d.inl.h"

// FUNCTION: BETA10 0x1005a590
int Matrix4::Invert(Matrix4& p_mat)
{
	// Inlined at LEGO1 0x1006b2d3

	float copyData[4][4];
	Matrix4 copy(copyData);
	copy = *this;

	p_mat.SetIdentity();

	for (int i = 0; i < 4; i++) {
		int pivotColumn = i;
		int column;

		for (column = i + 1; column < 4; column++) {
			if (fabs(copy[pivotColumn][i]) < fabs(copy[column][i])) {
				pivotColumn = column;
			}
		}

		if (pivotColumn != i) {
			copy.Swap(pivotColumn, i);
			p_mat.Swap(pivotColumn, i);
		}

		if (copy[i][i] < 0.001f && copy[i][i] > -0.001f) {
			// FAILURE from mxtypes.h
			return -1;
		}

		float pivotValue = copy[i][i];
		int k;

		for (k = 0; k < 4; k++) {
			p_mat[i][k] /= pivotValue;
		}

		for (k = 0; k < 4; k++) {
			copy[i][k] /= pivotValue;
		}

		for (column = 0; column < 4; column++) {
			if (i != column) {
				float tempColumn[4];

				for (k = 0; k < 4; k++) {
					tempColumn[k] = p_mat[i][k] * copy[column][i];
				}

				for (k = 0; k < 4; k++) {
					p_mat[column][k] -= tempColumn[k];
				}

				for (k = 0; k < 4; k++) {
					tempColumn[k] = copy[i][k] * copy[column][i];
				}

				for (k = 0; k < 4; k++) {
					copy[column][k] -= tempColumn[k];
				}
			}
		}
	}

	// SUCCESS from mxtypes.h
	return 0;
}

// FUNCTION: LEGO1 0x1006b500
// FUNCTION: BETA10 0x1005aa20
void Matrix4::Swap(int p_d1, int p_d2)
{
	// This function is affected by entropy even in debug builds
	int i;
	float e;
	for (i = 0; i < 4; i++) {
		e = m_data[p_d1][i];
		m_data[p_d1][i] = m_data[p_d2][i];
		m_data[p_d2][i] = e;
	}
}

#endif // MXMATRIX_H
