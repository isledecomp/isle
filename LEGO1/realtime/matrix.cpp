
#include "matrix.h"

#include "decomp.h"
#include "math.h"

#include <memory.h>

DECOMP_SIZE_ASSERT(Matrix4, 0x40);
DECOMP_SIZE_ASSERT(Matrix4Impl, 0x8);
DECOMP_SIZE_ASSERT(Matrix4Data, 0x48);

// FUNCTION: LEGO1 0x10002320
void Matrix4Impl::EqualsMatrixData(const Matrix4& p_matrix)
{
	*m_data = p_matrix;
}

// FUNCTION: LEGO1 0x10002340
void Matrix4Impl::EqualsMatrixImpl(const Matrix4Impl* p_other)
{
	*m_data = *p_other->m_data;
}

// FUNCTION: LEGO1 0x10002360
void Matrix4Impl::AnotherSetData(Matrix4& p_data)
{
	m_data = &p_data;
}

// FUNCTION: LEGO1 0x10002370
void Matrix4Impl::SetData(Matrix4& p_data)
{
	m_data = &p_data;
}

// FUNCTION: LEGO1 0x10002380
const Matrix4* Matrix4Impl::GetData() const
{
	return m_data;
}

// FUNCTION: LEGO1 0x10002390
Matrix4* Matrix4Impl::GetData()
{
	return m_data;
}

// FUNCTION: LEGO1 0x100023a0
const float* Matrix4Impl::Element(int p_row, int p_col) const
{
	return &(*m_data)[p_row][p_col];
}

// FUNCTION: LEGO1 0x100023c0
float* Matrix4Impl::Element(int p_row, int p_col)
{
	return &(*m_data)[p_row][p_col];
}

// FUNCTION: LEGO1 0x100023e0
void Matrix4Impl::Clear()
{
	memset(m_data, 0, 16 * sizeof(float));
}

// FUNCTION: LEGO1 0x100023f0
void Matrix4Impl::SetIdentity()
{
	Clear();
	(*m_data)[0][0] = 1.0f;
	(*m_data)[1][1] = 1.0f;
	(*m_data)[2][2] = 1.0f;
	(*m_data)[3][3] = 1.0f;
}

// FUNCTION: LEGO1 0x10002430
Matrix4Impl* Matrix4Impl::operator+=(const Matrix4& p_matrix)
{
	for (int i = 0; i < 16; ++i)
		((float*) m_data)[i] += ((float*) &p_matrix)[i];
	return this;
}

// Matches but instructions are significantly out of order. Probably not wrong
// code given that the very similar SetTranslation does match.
// FUNCTION: LEGO1 0x10002460
void Matrix4Impl::TranslateBy(const float* p_x, const float* p_y, const float* p_z)
{
	((float*) m_data)[12] += *p_x;
	((float*) m_data)[13] += *p_y;
	((float*) m_data)[14] += *p_z;
}

// FUNCTION: LEGO1 0x100024a0
void Matrix4Impl::SetTranslation(const float* p_x, const float* p_y, const float* p_z)
{
	(*m_data)[3][0] = *p_x;
	(*m_data)[3][1] = *p_y;
	(*m_data)[3][2] = *p_z;
}

// FUNCTION: LEGO1 0x100024d0
void Matrix4Impl::EqualsDataProduct(const Matrix4& p_a, const Matrix4& p_b)
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

// FUNCTION: LEGO1 0x10002530
void Matrix4Impl::EqualsMxProduct(const Matrix4Impl* p_a, const Matrix4Impl* p_b)
{
	EqualsDataProduct(*p_a->m_data, *p_b->m_data);
}

// Not close, Ghidra struggles understinging this method so it will have to
// be manually worked out. Included since I at least figured out what it was
// doing with rotateIndex and what overall operation it's trying to do.
// STUB: LEGO1 0x10002550
void Matrix4Impl::ToQuaternion(Vector4Impl* p_outQuat)
{
	/*
	float trace = m_data[0] + m_data[5] + m_data[10];
	if (trace > 0) {
		trace = sqrt(trace + 1.0);
		p_outQuat->GetData()[3] = trace * 0.5f;
		p_outQuat->GetData()[0] = (m_data[9] - m_data[6]) * trace;
		p_outQuat->GetData()[1] = (m_data[2] - m_data[8]) * trace;
		p_outQuat->GetData()[2] = (m_data[4] - m_data[1]) * trace;
		return;
	}

	// ~GLOBAL: LEGO1 0x100d4090
	static int rotateIndex[] = {1, 2, 0};

	// Largest element along the trace
	int largest = m_data[0] < m_data[5];
	if (*Element(largest, largest) < m_data[10])
		largest = 2;

	int next = rotateIndex[largest];
	int nextNext = rotateIndex[next];
	float valueA = *Element(nextNext, nextNext);
	float valueB = *Element(next, next);
	float valueC = *Element(largest, largest);

	// Above is somewhat decomped, below is pure speculation since the automatic
	// decomp becomes very garbled.
	float traceValue = sqrt(valueA - valueB - valueC + 1.0);

	p_outQuat->GetData()[largest] = traceValue * 0.5f;
	traceValue = 0.5f / traceValue;

	p_outQuat->GetData()[3] = (m_data[next + 4 * nextNext] - m_data[nextNext + 4 * next]) * traceValue;
	p_outQuat->GetData()[next] = (m_data[next + 4 * largest] + m_data[largest + 4 * next]) * traceValue;
	p_outQuat->GetData()[nextNext] = (m_data[nextNext + 4 * largest] + m_data[largest + 4 * nextNext]) * traceValue;
	*/
}

// No idea what this function is doing and it will be hard to tell until
// we have a confirmed usage site.
// STUB: LEGO1 0x10002710
int Matrix4Impl::FromQuaternion(const Vector4Impl& p_vec)
{
	return -1;
}

// FUNCTION: LEGO1 0x10002850
void Matrix4Impl::operator=(const Matrix4Impl& p_other)
{
	EqualsMatrixImpl(&p_other);
}

// FUNCTION: LEGO1 0x10002860
void Matrix4Data::operator=(const Matrix4Data& p_other)
{
	EqualsMatrixImpl(&p_other);
}
