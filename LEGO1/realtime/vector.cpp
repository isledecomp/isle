
#include "vector.h"

#include "../decomp.h"

#include <math.h>
#include <memory.h>

DECOMP_SIZE_ASSERT(Vector2Impl, 0x8);
DECOMP_SIZE_ASSERT(Vector3Impl, 0x8);
DECOMP_SIZE_ASSERT(Vector4Impl, 0x8);
DECOMP_SIZE_ASSERT(Vector3Data, 0x14);
DECOMP_SIZE_ASSERT(Vector4Data, 0x18);

// OFFSET: LEGO1 0x100020a0
const float* Vector2Impl::GetData() const
{
	return m_data;
}

// OFFSET: LEGO1 0x10002090
float* Vector2Impl::GetData()
{
	return m_data;
}

// OFFSET: LEGO1 0x10002130
float Vector2Impl::Dot(Vector2Impl* p_a, float* p_b) const
{
	return DotImpl(p_a->m_data, p_b);
}

// OFFSET: LEGO1 0x10002110
float Vector2Impl::Dot(float* p_a, Vector2Impl* p_b) const
{
	return DotImpl(p_a, p_b->m_data);
}

// OFFSET: LEGO1 0x100020f0
float Vector2Impl::Dot(Vector2Impl* p_a, Vector2Impl* p_b) const
{
	return DotImpl(p_a->m_data, p_b->m_data);
}

// OFFSET: LEGO1 0x100020d0
float Vector2Impl::Dot(float* p_a, float* p_b) const
{
	return DotImpl(p_a, p_b);
}

// OFFSET: LEGO1 0x10002160
int Vector2Impl::Unitize()
{
	float sq = LenSquared();
	if (sq > 0.0f) {
		float root = sqrt(sq);
		if (root > 0) {
			DivScalarImpl(&root);
			return 0;
		}
	}
	return -1;
}

// OFFSET: LEGO1 0x100021e0
void Vector2Impl::AddVector(Vector2Impl* p_other)
{
	AddVectorImpl(p_other->m_data);
}

// OFFSET: LEGO1 0x100021d0
void Vector2Impl::AddVector(float* p_other)
{
	AddVectorImpl(p_other);
}

// OFFSET: LEGO1 0x100021c0
void Vector2Impl::AddScalar(float p_value)
{
	AddScalarImpl(p_value);
}

// OFFSET: LEGO1 0x10002200
void Vector2Impl::SubVector(Vector2Impl* p_other)
{
	SubVectorImpl(p_other->m_data);
}

// OFFSET: LEGO1 0x100021f0
void Vector2Impl::SubVector(float* p_other)
{
	SubVectorImpl(p_other);
}

// OFFSET: LEGO1 0x10002230
void Vector2Impl::MullScalar(float* p_value)
{
	MullScalarImpl(p_value);
}

// OFFSET: LEGO1 0x10002220
void Vector2Impl::MullVector(Vector2Impl* p_other)
{
	MullVectorImpl(p_other->m_data);
}

// OFFSET: LEGO1 0x10002210
void Vector2Impl::MullVector(float* p_other)
{
	MullVectorImpl(p_other);
}

// OFFSET: LEGO1 0x10002240
void Vector2Impl::DivScalar(float* p_value)
{
	DivScalarImpl(p_value);
}

// OFFSET: LEGO1 0x10002260
void Vector2Impl::SetVector(Vector2Impl* p_other)
{
	EqualsImpl(p_other->m_data);
}

// OFFSET: LEGO1 0x10002250
void Vector2Impl::SetVector(float* p_other)
{
	EqualsImpl(p_other);
}

// OFFSET: LEGO1 0x10001fa0
void Vector2Impl::AddScalarImpl(float p_value)
{
	m_data[0] += p_value;
	m_data[1] += p_value;
}

// OFFSET: LEGO1 0x10001f80
void Vector2Impl::AddVectorImpl(float* p_value)
{
	m_data[0] += p_value[0];
	m_data[1] += p_value[1];
}

// OFFSET: LEGO1 0x10001fc0
void Vector2Impl::SubVectorImpl(float* p_value)
{
	m_data[0] -= p_value[0];
	m_data[1] -= p_value[1];
}

// OFFSET: LEGO1 0x10002000
void Vector2Impl::MullScalarImpl(float* p_value)
{
	m_data[0] *= *p_value;
	m_data[1] *= *p_value;
}

// OFFSET: LEGO1 0x10001fe0
void Vector2Impl::MullVectorImpl(float* p_value)
{
	m_data[0] *= p_value[0];
	m_data[1] *= p_value[1];
}

// OFFSET: LEGO1 0x10002020
void Vector2Impl::DivScalarImpl(float* p_value)
{
	m_data[0] /= *p_value;
	m_data[1] /= *p_value;
}

// OFFSET: LEGO1 0x10002040
float Vector2Impl::DotImpl(float* p_a, float* p_b) const
{
	return p_b[0] * p_a[0] + p_b[1] * p_a[1];
}

// OFFSET: LEGO1 0x10002070
void Vector2Impl::EqualsImpl(float* p_data)
{
	float* vec = m_data;
	vec[0] = p_data[0];
	vec[1] = p_data[1];
}

// OFFSET: LEGO1 0x100020b0
void Vector2Impl::Clear()
{
	float* vec = m_data;
	vec[0] = 0.0f;
	vec[1] = 0.0f;
}

// OFFSET: LEGO1 0x10002150
float Vector2Impl::LenSquared() const
{
	return m_data[0] * m_data[0] + m_data[1] * m_data[1];
}

// OFFSET: LEGO1 0x10003a90
void Vector3Impl::AddScalarImpl(float p_value)
{
	m_data[0] += p_value;
	m_data[1] += p_value;
	m_data[2] += p_value;
}

// OFFSET: LEGO1 0x10003a60
void Vector3Impl::AddVectorImpl(float* p_value)
{
	m_data[0] += p_value[0];
	m_data[1] += p_value[1];
	m_data[2] += p_value[2];
}

// OFFSET: LEGO1 0x10003ac0
void Vector3Impl::SubVectorImpl(float* p_value)
{
	m_data[0] -= p_value[0];
	m_data[1] -= p_value[1];
	m_data[2] -= p_value[2];
}

// OFFSET: LEGO1 0x10003b20
void Vector3Impl::MullScalarImpl(float* p_value)
{
	m_data[0] *= *p_value;
	m_data[1] *= *p_value;
	m_data[2] *= *p_value;
}

// OFFSET: LEGO1 0x10003af0
void Vector3Impl::MullVectorImpl(float* p_value)
{
	m_data[0] *= p_value[0];
	m_data[1] *= p_value[1];
	m_data[2] *= p_value[2];
}

// OFFSET: LEGO1 0x10003b50
void Vector3Impl::DivScalarImpl(float* p_value)
{
	m_data[0] /= *p_value;
	m_data[1] /= *p_value;
	m_data[2] /= *p_value;
}

// OFFSET: LEGO1 0x10003b80
float Vector3Impl::DotImpl(float* p_a, float* p_b) const
{
	return p_a[0] * p_b[0] + p_a[2] * p_b[2] + p_a[1] * p_b[1];
}

// OFFSET: LEGO1 0x10003ba0
void Vector3Impl::EqualsImpl(float* p_data)
{
	float* vec = m_data;
	vec[0] = p_data[0];
	vec[1] = p_data[1];
	vec[2] = p_data[2];
}

// OFFSET: LEGO1 0x10003bc0
void Vector3Impl::Clear()
{
	float* vec = m_data;
	vec[0] = 0.0f;
	vec[1] = 0.0f;
	vec[2] = 0.0f;
}

// OFFSET: LEGO1 0x10003bd0
float Vector3Impl::LenSquared() const
{
	return m_data[1] * m_data[1] + m_data[0] * m_data[0] + m_data[2] * m_data[2];
}

// OFFSET: LEGO1 0x10002270
void Vector3Impl::EqualsCrossImpl(float* p_a, float* p_b)
{
	m_data[0] = p_a[1] * p_b[2] - p_a[2] * p_b[1];
	m_data[1] = p_a[2] * p_b[0] - p_a[0] * p_b[2];
	m_data[2] = p_a[0] * p_b[1] - p_a[1] * p_b[0];
}

// OFFSET: LEGO1 0x10002300
void Vector3Impl::EqualsCross(float* p_a, Vector3Impl* p_b)
{
	EqualsCrossImpl(p_a, p_b->m_data);
}

// OFFSET: LEGO1 0x100022e0
void Vector3Impl::EqualsCross(Vector3Impl* p_a, float* p_b)
{
	EqualsCrossImpl(p_a->m_data, p_b);
}

// OFFSET: LEGO1 0x100022c0
void Vector3Impl::EqualsCross(Vector3Impl* p_a, Vector3Impl* p_b)
{
	EqualsCrossImpl(p_a->m_data, p_b->m_data);
}

// OFFSET: LEGO1 0x10003bf0
void Vector3Impl::EqualsScalar(float* p_value)
{
	m_data[0] = *p_value;
	m_data[1] = *p_value;
	m_data[2] = *p_value;
}

// OFFSET: LEGO1 0x100028b0
void Vector4Impl::AddScalarImpl(float p_value)
{
	m_data[0] += p_value;
	m_data[1] += p_value;
	m_data[2] += p_value;
	m_data[3] += p_value;
}

// OFFSET: LEGO1 0x10002870
void Vector4Impl::AddVectorImpl(float* p_value)
{
	m_data[0] += p_value[0];
	m_data[1] += p_value[1];
	m_data[2] += p_value[2];
	m_data[3] += p_value[3];
}

// OFFSET: LEGO1 0x100028f0
void Vector4Impl::SubVectorImpl(float* p_value)
{
	m_data[0] -= p_value[0];
	m_data[1] -= p_value[1];
	m_data[2] -= p_value[2];
	m_data[3] -= p_value[3];
}

// OFFSET: LEGO1 0x10002970
void Vector4Impl::MullScalarImpl(float* p_value)
{
	m_data[0] *= *p_value;
	m_data[1] *= *p_value;
	m_data[2] *= *p_value;
	m_data[3] *= *p_value;
}

// OFFSET: LEGO1 0x10002930
void Vector4Impl::MullVectorImpl(float* p_value)
{
	m_data[0] *= p_value[0];
	m_data[1] *= p_value[1];
	m_data[2] *= p_value[2];
	m_data[3] *= p_value[3];
}

// OFFSET: LEGO1 0x100029b0
void Vector4Impl::DivScalarImpl(float* p_value)
{
	m_data[0] /= *p_value;
	m_data[1] /= *p_value;
	m_data[2] /= *p_value;
	m_data[3] /= *p_value;
}

// OFFSET: LEGO1 0x100029f0
float Vector4Impl::DotImpl(float* p_a, float* p_b) const
{
	return p_a[0] * p_b[0] + p_a[2] * p_b[2] + (p_a[1] * p_b[1] + p_a[3] * p_b[3]);
}

// OFFSET: LEGO1 0x10002a20
void Vector4Impl::EqualsImpl(float* p_data)
{
	float* vec = m_data;
	vec[0] = p_data[0];
	vec[1] = p_data[1];
	vec[2] = p_data[2];
	vec[3] = p_data[3];
}

// OFFSET: LEGO1 0x10002b00
void Vector4Impl::Clear()
{
	float* vec = m_data;
	vec[0] = 0.0f;
	vec[1] = 0.0f;
	vec[2] = 0.0f;
	vec[3] = 0.0f;
}

// OFFSET: LEGO1 0x10002b20
float Vector4Impl::LenSquared() const
{
	return m_data[1] * m_data[1] + m_data[0] * m_data[0] + m_data[2] * m_data[2] + m_data[3] * m_data[3];
}

// OFFSET: LEGO1 0x10002b40
void Vector4Impl::EqualsScalar(float* p_value)
{
	m_data[0] = *p_value;
	m_data[1] = *p_value;
	m_data[2] = *p_value;
	m_data[3] = *p_value;
}

// OFFSET: LEGO1 0x10002ae0
void Vector4Impl::SetMatrixProduct(Vector4Impl* p_a, float* p_b)
{
	SetMatrixProductImpl(p_a->m_data, p_b);
}

// OFFSET: LEGO1 0x10002a40
void Vector4Impl::SetMatrixProductImpl(float* p_vec, float* p_mat)
{
	m_data[0] = p_vec[0] * p_mat[0] + p_vec[1] * p_mat[4] + p_vec[2] * p_mat[8] + p_vec[3] * p_mat[12];
	m_data[1] = p_vec[0] * p_mat[1] + p_vec[1] * p_mat[5] + p_vec[2] * p_mat[9] + p_vec[4] * p_mat[13];
	m_data[2] = p_vec[0] * p_mat[2] + p_vec[1] * p_mat[6] + p_vec[2] * p_mat[10] + p_vec[4] * p_mat[14];
	m_data[3] = p_vec[0] * p_mat[3] + p_vec[1] * p_mat[7] + p_vec[2] * p_mat[11] + p_vec[4] * p_mat[15];
}

// Note close yet, included because I'm at least confident I know what operation
// it's trying to do.
// OFFSET: LEGO1 0x10002b70 STUB
int Vector4Impl::NormalizeQuaternion()
{
	float* v = m_data;
	float magnitude = v[1] * v[1] + v[2] * v[2] + v[0] * v[0];
	if (magnitude > 0.0f) {
		float theta = v[3] * 0.5f;
		v[3] = cos(theta);
		float frac = sin(theta);
		magnitude = frac / sqrt(magnitude);
		v[0] *= magnitude;
		v[1] *= magnitude;
		v[2] *= magnitude;
		return 0;
	}
	return -1;
}

// OFFSET: LEGO1 0x10002bf0
void Vector4Impl::UnknownQuaternionOp(Vector4Impl* p_a, Vector4Impl* p_b)
{
	float* bDat = p_b->m_data;
	float* aDat = p_a->m_data;

	this->m_data[3] = aDat[3] * bDat[3] - (bDat[0] * aDat[0] + aDat[2] * bDat[2] + aDat[1] * aDat[1]);
	this->m_data[0] = bDat[2] * aDat[1] - bDat[1] * aDat[2];
	this->m_data[1] = aDat[2] * bDat[0] - bDat[2] * aDat[0];
	this->m_data[2] = bDat[1] * aDat[0] - aDat[1] * bDat[0];

	m_data[0] = p_b->m_data[3] * p_a->m_data[0] + p_a->m_data[3] * p_b->m_data[0] + m_data[0];
	m_data[1] = p_b->m_data[1] * p_a->m_data[3] + p_a->m_data[1] * p_b->m_data[3] + m_data[1];
	m_data[2] = p_b->m_data[2] * p_a->m_data[3] + p_a->m_data[2] * p_b->m_data[3] + m_data[2];
}
