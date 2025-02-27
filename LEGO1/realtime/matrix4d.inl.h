#ifndef MATRIX4D_H
#define MATRIX4D_H

#include "matrix.h"

#include <math.h>
#include <memory.h>

// FUNCTION: LEGO1 0x10002320
// FUNCTION: BETA10 0x1000fcb0
void Matrix4::Equals(float (*p_data)[4])
{
	memcpy(m_data, p_data, sizeof(float) * 4 * 4);
}

// FUNCTION: LEGO1 0x10002340
// FUNCTION: BETA10 0x1000fcf0
void Matrix4::Equals(const Matrix4& p_matrix)
{
	memcpy(m_data, p_matrix.m_data, sizeof(float) * 4 * 4);
}

// FUNCTION: LEGO1 0x10002360
// FUNCTION: BETA10 0x1000fd30
void Matrix4::SetData(float (*p_data)[4])
{
	m_data = p_data;
}

// FUNCTION: LEGO1 0x10002370
// FUNCTION: BETA10 0x1000fd60
void Matrix4::SetData(UnknownMatrixType& p_matrix)
{
	m_data = p_matrix.m_data;
}

// FUNCTION: LEGO1 0x10002380
// FUNCTION: BETA10 0x1000fd90
float (*Matrix4::GetData())[4]
{
	return m_data;
}

// FUNCTION: LEGO1 0x10002390
// FUNCTION: BETA10 0x1000fdc0
float (*Matrix4::GetData() const)[4]
{
	return m_data;
}

// FUNCTION: LEGO1 0x100023a0
// FUNCTION: BETA10 0x1000fdf0
float* Matrix4::Element(int p_row, int p_col)
{
	return &m_data[p_row][p_col];
}

// FUNCTION: LEGO1 0x100023c0
// FUNCTION: BETA10 0x1000fe30
const float* Matrix4::Element(int p_row, int p_col) const
{
	return &m_data[p_row][p_col];
}

// FUNCTION: LEGO1 0x100023e0
// FUNCTION: BETA10 0x1000fe70
void Matrix4::Clear()
{
	memset(m_data, 0, 16 * sizeof(float));
}

// FUNCTION: LEGO1 0x100023f0
// FUNCTION: BETA10 0x1000feb0
void Matrix4::SetIdentity()
{
	Clear();
	m_data[0][0] = 1.0f;
	m_data[1][1] = 1.0f;
	m_data[2][2] = 1.0f;
	m_data[3][3] = 1.0f;
}

// FUNCTION: LEGO1 0x10002420
// FUNCTION: BETA10 0x1000ff20
void Matrix4::operator=(const Matrix4& p_matrix)
{
	Equals(p_matrix);
}

// FUNCTION: LEGO1 0x10002430
// FUNCTION: BETA10 0x1000ff50
Matrix4& Matrix4::operator+=(float (*p_data)[4])
{
	for (int i = 0; i < 16; i++) {
		((float*) m_data)[i] += ((float*) p_data)[i];
	}

	return *this;
}

// FUNCTION: LEGO1 0x10002460
// FUNCTION: BETA10 0x1000ffc0
void Matrix4::TranslateBy(const float& p_x, const float& p_y, const float& p_z)
{
	m_data[3][0] += p_x;
	m_data[3][1] += p_y;
	m_data[3][2] += p_z;
}

// FUNCTION: LEGO1 0x100024a0
// FUNCTION: BETA10 0x10010040
void Matrix4::SetTranslation(const float& p_x, const float& p_y, const float& p_z)
{
	m_data[3][0] = p_x;
	m_data[3][1] = p_y;
	m_data[3][2] = p_z;
}

// FUNCTION: LEGO1 0x100024d0
// FUNCTION: BETA10 0x100100a0
void Matrix4::Product(float (*p_a)[4], float (*p_b)[4])
{
	float* cur = (float*) m_data;

	for (int row = 0; row < 4; row++) {
		for (int col = 0; col < 4; col++) {
			*cur = 0.0f;
			for (int k = 0; k < 4; k++) {
				*cur += p_a[row][k] * p_b[k][col];
			}
			cur++;
		}
	}
}

// FUNCTION: LEGO1 0x10002530
// FUNCTION: BETA10 0x10010180
void Matrix4::Product(const Matrix4& p_a, const Matrix4& p_b)
{
	Product(p_a.m_data, p_b.m_data);
}

// FUNCTION: LEGO1 0x10002550
// FUNCTION: BETA10 0x100101c0
void Matrix4::ToQuaternion(Vector4& p_outQuat)
{
	float trace;
	float localc = m_data[0][0] + m_data[1][1] + m_data[2][2];

	if (localc > 0) {
		trace = (float) sqrt(localc + 1.0);
		p_outQuat[3] = trace * 0.5f;
		trace = 0.5f / trace;
		p_outQuat[0] = (m_data[2][1] - m_data[1][2]) * trace;
		p_outQuat[1] = (m_data[0][2] - m_data[2][0]) * trace;
		p_outQuat[2] = (m_data[1][0] - m_data[0][1]) * trace;
	}
	else {
		// GLOBAL: LEGO1 0x100d4090
		static int rotateIndex[] = {1, 2, 0};

		// Largest element along the trace
		int largest = 0;
		if (m_data[0][0] < m_data[1][1]) {
			largest = 1;
		}
		if (*Element(largest, largest) < m_data[2][2]) {
			largest = 2;
		}

		int next = rotateIndex[largest];
		int nextNext = rotateIndex[next];

		trace = (float) sqrt(*Element(largest, largest) - (*Element(nextNext, nextNext) + *Element(next, next)) + 1.0);

		p_outQuat[largest] = trace * 0.5f;
		trace = 0.5f / trace;

		p_outQuat[3] = (*Element(nextNext, next) - *Element(next, nextNext)) * trace;
		p_outQuat[next] = (*Element(largest, next) + *Element(next, largest)) * trace;
		p_outQuat[nextNext] = (*Element(largest, nextNext) + *Element(nextNext, largest)) * trace;
	}
}

// FUNCTION: LEGO1 0x10002710
// FUNCTION: BETA10 0x10010550
int Matrix4::FromQuaternion(const Vector4& p_vec)
{
	float local14 = p_vec.LenSquared();

	if (local14 > 0.0f) {
		local14 = 2.0f / local14;

		float local24 = p_vec[0] * local14;
		float local34 = p_vec[1] * local14;
		float local10 = p_vec[2] * local14;

		float local28 = p_vec[3] * local24;
		float local2c = p_vec[3] * local34;
		float local30 = p_vec[3] * local10;

		float local38 = p_vec[0] * local24;
		float local8 = p_vec[0] * local34;
		float localc = p_vec[0] * local10;

		float local18 = p_vec[1] * local34;
		float local1c = p_vec[1] * local10;
		float local20 = p_vec[2] * local10;

		m_data[0][0] = 1.0f - (local18 + local20);
		m_data[1][0] = local8 + local30;
		m_data[2][0] = localc - local2c;

		m_data[0][1] = local8 - local30;
		m_data[1][1] = 1.0f - (local38 + local20);
		m_data[2][1] = local1c + local28;

		m_data[0][2] = local2c + localc;
		m_data[1][2] = local1c - local28;
		m_data[2][2] = 1.0f - (local18 + local38);

		m_data[3][0] = 0.0f;
		m_data[3][1] = 0.0f;
		m_data[3][2] = 0.0f;
		m_data[3][3] = 1.0f;

		m_data[0][3] = 0.0f;
		m_data[1][3] = 0.0f;
		m_data[2][3] = 0.0f;
		return 0;
	}
	else {
		return -1;
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

// FUNCTION: BETA10 0x1005a590
int Matrix4::BETA_1005a590(Matrix4& p_mat)
{
	float local5c[4][4];
	Matrix4 localc(local5c);
	localc = *this;

	p_mat.SetIdentity();

	for (int i = 0; i < 4; i++) {
		int local1c = i;
		int local10;

		for (local10 = i + 1; local10 < 4; local10++) {
			if (fabs(localc[local1c][i]) < fabs(localc[local10][i])) {
				local1c = local10;
			}
		}

		if (local1c != i) {
			localc.Swap(local1c, i);
			p_mat.Swap(local1c, i);
		}

		if (localc[i][i] < 0.001f && localc[i][i] > -0.001f) {
			return -1;
		}

		float local60 = localc[i][i];
		int local18;

		for (local18 = 0; local18 < 4; local18++) {
			p_mat[i][local18] /= local60;
		}

		for (local18 = 0; local18 < 4; local18++) {
			localc[i][local18] /= local60;
		}

		for (local10 = 0; local10 < 4; local10++) {
			if (i != local10) {
				float afStack70[4];

				for (local18 = 0; local18 < 4; local18++) {
					afStack70[local18] = p_mat[i][local18] * localc[local10][i];
				}

				for (local18 = 0; local18 < 4; local18++) {
					p_mat[local10][local18] -= afStack70[local18];
				}

				for (local18 = 0; local18 < 4; local18++) {
					afStack70[local18] = localc[i][local18] * localc[local10][i];
				}

				for (local18 = 0; local18 < 4; local18++) {
					localc[local10][local18] -= afStack70[local18];
				}
			}
		}
	}

	return 0;
}

// FUNCTION: LEGO1 0x1006b500
void Matrix4::Swap(int p_d1, int p_d2)
{
	for (int i = 0; i < 4; i++) {
		float e = m_data[p_d1][i];
		m_data[p_d1][i] = m_data[p_d2][i];
		m_data[p_d2][i] = e;
	}
}

#endif // MATRIX4D_H
