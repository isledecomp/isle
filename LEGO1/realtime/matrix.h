#ifndef MATRIX_H
#define MATRIX_H

#include "memory.h"
#include "vector.h"
/*
 * A simple array of four Vector4s that can be indexed into.
 */
class Matrix4 {
public:
	float rows[4][4]; // storage is public for easy access

	inline Matrix4() {}
	/*
	Matrix4(const Vector4& x_axis, const Vector4& y_axis, const Vector4& z_axis, const Vector4& position)
	{
		rows[0] = x_axis;
		rows[1] = y_axis;
		rows[2] = z_axis;
		rows[3] = position;
	}
	Matrix4(const float m[4][4])
	{
		rows[0] = m[0];
		rows[1] = m[1];
		rows[2] = m[2];
		rows[3] = m[3];
	}
	*/
	const float* operator[](long i) const { return rows[i]; }
	float* operator[](long i) { return rows[i]; }
};

// VTABLE: LEGO1 0x100d4350
// SIZE 0x8
class Matrix4Impl {
public:
	inline Matrix4Impl(Matrix4& p_data) { m_data = &p_data; }

	// FUNCTION: LEGO1 0x10002340
	virtual void EqualsMatrixImpl(const Matrix4Impl* p_other) { *m_data = *p_other->m_data; }

	// FUNCTION: LEGO1 0x10002320
	virtual void EqualsMatrixData(const Matrix4& p_matrix) { *m_data = p_matrix; }

	// FUNCTION: LEGO1 0x10002370
	virtual void SetData(Matrix4& p_data) { m_data = &p_data; }

	// FUNCTION: LEGO1 0x10002360
	virtual void AnotherSetData(Matrix4& p_data) { m_data = &p_data; }

	// FUNCTION: LEGO1 0x10002390
	virtual Matrix4* GetData() { return m_data; }

	// FUNCTION: LEGO1 0x10002380
	virtual const Matrix4* GetData() const { return m_data; }

	// FUNCTION: LEGO1 0x100023c0
	virtual float* Element(int p_row, int p_col) { return &(*m_data)[p_row][p_col]; }

	// FUNCTION: LEGO1 0x100023a0
	virtual const float* Element(int p_row, int p_col) const { return &(*m_data)[p_row][p_col]; }

	// FUNCTION: LEGO1 0x100023e0
	virtual void Clear() { memset(m_data, 0, 16 * sizeof(float)); }

	// FUNCTION: LEGO1 0x100023f0
	virtual inline void SetIdentity()
	{
		Clear();
		(*m_data)[0][0] = 1.0f;
		(*m_data)[1][1] = 1.0f;
		(*m_data)[2][2] = 1.0f;
		(*m_data)[3][3] = 1.0f;
	}

	// FUNCTION: LEGO1 0x10002420
	virtual void operator=(const Matrix4Impl& p_other) { EqualsMatrixImpl(&p_other); }

	// FUNCTION: LEGO1 0x10002430
	virtual Matrix4Impl* operator+=(const Matrix4& p_matrix)
	{
		for (int i = 0; i < 16; ++i)
			((float*) m_data)[i] += ((float*) &p_matrix)[i];
		return this;
	}

	// Matches but instructions are significantly out of order. Probably not wrong
	// code given that the very similar SetTranslation does match.
	// FUNCTION: LEGO1 0x10002460
	virtual void TranslateBy(const float* p_x, const float* p_y, const float* p_z)
	{
		((float*) m_data)[12] += *p_x;
		((float*) m_data)[13] += *p_y;
		((float*) m_data)[14] += *p_z;
	}

	// FUNCTION: LEGO1 0x100024a0
	virtual void SetTranslation(const float* p_x, const float* p_y, const float* p_z)
	{
		(*m_data)[3][0] = *p_x;
		(*m_data)[3][1] = *p_y;
		(*m_data)[3][2] = *p_z;
	}

	// FUNCTION: LEGO1 0x10002530
	virtual void EqualsMxProduct(const Matrix4Impl* p_a, const Matrix4Impl* p_b)
	{
		EqualsDataProduct(*p_a->m_data, *p_b->m_data);
	}

	// FUNCTION: LEGO1 0x100024d0
	virtual void EqualsDataProduct(const Matrix4& p_a, const Matrix4& p_b)
	{
		float* cur = (float*) m_data;
		for (int row = 0; row < 4; ++row) {
			for (int col = 0; col < 4; ++col) {
				*cur = 0.0f;
				for (int k = 0; k < 4; ++k) {
					*cur += p_a[row][k] * p_b[k][col];
				}
				cur++;
			}
		}
	}

	// FUNCTION: LEGO1 0x10002550
	virtual void ToQuaternion(Vector4Impl& p_outQuat)
	{

		float trace = TRACE3(*m_data);
		if (trace > 0) {
			trace = sqrt(trace + 1.0);
			p_outQuat[3] = trace * 0.5f;
			trace = 0.5f / trace;
			p_outQuat[0] = ((*m_data)[2][1] - (*m_data)[1][2]) * trace;
			p_outQuat[1] = ((*m_data)[0][2] - (*m_data)[2][0]) * trace;
			p_outQuat[2] = ((*m_data)[1][0] - (*m_data)[0][1]) * trace;
		}
		else {
			// FUNCTION: LEGO1 0x100d4090
			static int rotateIndex[] = {1, 2, 0};

			int i, j, k;
			i = 0;
			// Largest element along the trace
			if ((*m_data)[1][1] > (*m_data)[0][0])
				i = 1;
			if ((*m_data)[2][2] > *Element(i, i))
				i = 2;

			j = rotateIndex[i];
			k = rotateIndex[j];

			// Above is somewhat decomped, below is pure speculation since the automatic
			// decomp becomes very garbled.
			float traceValue = sqrt(*Element(i, i) - (*Element(j, j) + *Element(k, k)) + 1.0);

			p_outQuat[i] = traceValue * 0.5f;
			traceValue = 0.5f / traceValue;

			p_outQuat.GetData()[3] = traceValue * ((*m_data)[k][j] - (*m_data)[j][k]);
			p_outQuat.GetData()[j] = traceValue * (*m_data)[j][i] + (*m_data)[i][j];
			p_outQuat.GetData()[k] = traceValue * (*m_data)[k][i] + (*m_data)[i][k];
		}
	}

	// FUNCTION: LEGO1 0x10002710
	virtual int FromQuaternion(const Vector4Impl& p_quat)
	{
		float lensq;
		if ((lensq = p_quat.LenSquared()) > 0) {
			lensq = 2 / lensq;
			float XX = p_quat[0] * lensq;
			float YY = p_quat[1] * lensq;
			float ZZ = p_quat[2] * lensq;

			float WXX = p_quat[3] * XX;
			float XXX = p_quat[0] * XX;

			float WYY = p_quat[3] * YY;
			float XYY = p_quat[0] * YY;
			float YYY = p_quat[1] * YY;

			float WZZ = p_quat[3] * ZZ;
			float XZZ = p_quat[0] * ZZ;
			float YZZ = p_quat[1] * ZZ;
			float ZZZ = p_quat[2] * ZZ;

			(*m_data)[0][0] = 1 - (YYY + ZZZ);
			(*m_data)[1][0] = XYY + WZZ;
			(*m_data)[2][0] = XZZ - WYY;
			(*m_data)[0][1] = XYY - WZZ;
			(*m_data)[1][1] = 1 - (XXX + ZZZ);
			(*m_data)[2][1] = YZZ + WXX;
			(*m_data)[0][2] = XZZ + WYY;
			(*m_data)[1][2] = YZZ - WXX;
			(*m_data)[2][2] = 1 - (XXX + YYY);
			(*m_data)[3][0] = 0;
			(*m_data)[3][1] = 0;
			(*m_data)[3][2] = 0;
			(*m_data)[3][3] = 1;
			(*m_data)[0][3] = 0;
			(*m_data)[1][3] = 0;
			(*m_data)[2][3] = 0;
			return 0;
		}
		return -1;
	}

	inline float& operator[](size_t idx) { return ((float*) m_data)[idx]; }

protected:
	// TODO: Currently unclear whether this class contains a Matrix4* or float*.
	Matrix4* m_data;
};

// VTABLE: LEGO1 0x100d4300
// SIZE 0x48
class Matrix4Data : public Matrix4Impl {
public:
	inline Matrix4Data() : Matrix4Impl(m_matrix) {}
	inline Matrix4Data(Matrix4Data& p_other) : Matrix4Impl(m_matrix) { m_matrix = *p_other.m_data; }
	inline Matrix4& GetMatrix() { return *m_data; }

	// FUNCTION: LEGO1 0x10002850
	virtual void Matrix4Data::operator=(const Matrix4Impl& p_other) { EqualsMatrixImpl(&p_other); }

	// FUNCTION: LEGO1 0x10002860
	virtual void Matrix4Data::operator=(const Matrix4Data& p_other) { EqualsMatrixImpl(&p_other); }

	Matrix4 m_matrix;
};

#endif // MATRIX_H
