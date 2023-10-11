
#include "mxvector.h"

#include <math.h>
#include <memory.h>

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxVector2, 0x8);
DECOMP_SIZE_ASSERT(MxVector3, 0x8);
DECOMP_SIZE_ASSERT(MxVector4, 0x8);
DECOMP_SIZE_ASSERT(MxVector3Data, 0x14);
DECOMP_SIZE_ASSERT(MxVector4Data, 0x18);

// OFFSET: LEGO1 0x100020a0
const float *MxVector2::GetData() const
{
  return m_data;
}

// OFFSET: LEGO1 0x10002090
float *MxVector2::GetData()
{
  return m_data;
}

// OFFSET: LEGO1 0x10002130
float MxVector2::Dot(MxVector2 *p_a, float *p_b) const
{
  return DotImpl(p_a->m_data, p_b);
}

// OFFSET: LEGO1 0x10002110
float MxVector2::Dot(float *p_a, MxVector2 *p_b) const
{
  return DotImpl(p_a, p_b->m_data);
}

// OFFSET: LEGO1 0x100020f0
float MxVector2::Dot(MxVector2 *p_a, MxVector2 *p_b) const
{
  return DotImpl(p_a->m_data, p_b->m_data);
}

// OFFSET: LEGO1 0x100020d0
float MxVector2::Dot(float *p_a, float *p_b) const
{
  return DotImpl(p_a, p_b);
}

// OFFSET: LEGO1 0x10002160
MxResult MxVector2::Unitize()
{
  float sq = LenSquared();
  if (sq > 0.0f)
  {
    float root = sqrt(sq);
    if (root > 0)
    {
      DivScalarImpl(&root);
      return SUCCESS;
    }
  }
  return FAILURE;
}

// OFFSET: LEGO1 0x100021e0
void MxVector2::AddVector(MxVector2 *p_other)
{
  AddVectorImpl(p_other->m_data);
}

// OFFSET: LEGO1 0x100021d0
void MxVector2::AddVector(float *p_other)
{
  AddVectorImpl(p_other);
}

// OFFSET: LEGO1 0x100021c0
void MxVector2::AddScalar(float p_value)
{
  AddScalarImpl(p_value);
}

// OFFSET: LEGO1 0x10002200
void MxVector2::SubVector(MxVector2 *p_other)
{
  SubVectorImpl(p_other->m_data);
}

// OFFSET: LEGO1 0x100021f0
void MxVector2::SubVector(float *p_other)
{
  SubVectorImpl(p_other);
}

// OFFSET: LEGO1 0x10002230
void MxVector2::MullScalar(float *p_value)
{
  MullScalarImpl(p_value);
}

// OFFSET: LEGO1 0x10002220
void MxVector2::MullVector(MxVector2 *p_other)
{
  MullVectorImpl(p_other->m_data);
}

// OFFSET: LEGO1 0x10002210
void MxVector2::MullVector(float *p_other)
{
  MullVectorImpl(p_other);
}

// OFFSET: LEGO1 0x10002240
void MxVector2::DivScalar(float *p_value)
{
  DivScalarImpl(p_value);
}

// OFFSET: LEGO1 0x10002260
void MxVector2::SetVector(MxVector2 *p_other)
{
  EqualsImpl(p_other->m_data);
}

// OFFSET: LEGO1 0x10002250
void MxVector2::SetVector(float *p_other)
{
  EqualsImpl(p_other);
}

// OFFSET: LEGO1 0x10001fa0
void MxVector2::AddScalarImpl(float p_value)
{
  m_data[0] += p_value;
  m_data[1] += p_value;
}

// OFFSET: LEGO1 0x10001f80
void MxVector2::AddVectorImpl(float *p_value)
{
  m_data[0] += p_value[0];
  m_data[1] += p_value[1];
}

// OFFSET: LEGO1 0x10001fc0
void MxVector2::SubVectorImpl(float *p_value)
{
  m_data[0] -= p_value[0];
  m_data[1] -= p_value[1];
}

// OFFSET: LEGO1 0x10002000
void MxVector2::MullScalarImpl(float *p_value)
{
  m_data[0] *= *p_value;
  m_data[1] *= *p_value;
}

// OFFSET: LEGO1 0x10001fe0
void MxVector2::MullVectorImpl(float *p_value)
{
  m_data[0] *= p_value[0];
  m_data[1] *= p_value[1];
}

// OFFSET: LEGO1 0x10002020
void MxVector2::DivScalarImpl(float *p_value)
{
  m_data[0] /= *p_value;
  m_data[1] /= *p_value;
}

// OFFSET: LEGO1 0x10002040
float MxVector2::DotImpl(float *p_a, float *p_b) const
{
  return p_b[0] * p_a[0] + p_b[1] * p_a[1];
}

// OFFSET: LEGO1 0x10002070
void MxVector2::EqualsImpl(float *p_data)
{
  float *vec = m_data;
  vec[0] = p_data[0];
  vec[1] = p_data[1];
}

// OFFSET: LEGO1 0x100020b0
void MxVector2::Clear()
{
  float *vec = m_data;
  vec[0] = 0.0f;
  vec[1] = 0.0f;
}

// OFFSET: LEGO1 0x10002150
float MxVector2::LenSquared() const
{
  return m_data[0] * m_data[0] + m_data[1] * m_data[1];
}

// OFFSET: LEGO1 0x10003a90
void MxVector3::AddScalarImpl(float p_value)
{
  m_data[0] += p_value;
  m_data[1] += p_value;
  m_data[2] += p_value;
}

// OFFSET: LEGO1 0x10003a60
void MxVector3::AddVectorImpl(float *p_value)
{
  m_data[0] += p_value[0];
  m_data[1] += p_value[1];
  m_data[2] += p_value[2];
}

// OFFSET: LEGO1 0x10003ac0
void MxVector3::SubVectorImpl(float *p_value)
{
  m_data[0] -= p_value[0];
  m_data[1] -= p_value[1];
  m_data[2] -= p_value[2];
}

// OFFSET: LEGO1 0x10003b20
void MxVector3::MullScalarImpl(float *p_value)
{
  m_data[0] *= *p_value;
  m_data[1] *= *p_value;
  m_data[2] *= *p_value;
}

// OFFSET: LEGO1 0x10003af0
void MxVector3::MullVectorImpl(float *p_value)
{
  m_data[0] *= p_value[0];
  m_data[1] *= p_value[1];
  m_data[2] *= p_value[2];
}

// OFFSET: LEGO1 0x10003b50
void MxVector3::DivScalarImpl(float *p_value)
{
  m_data[0] /= *p_value;
  m_data[1] /= *p_value;
  m_data[2] /= *p_value;
}

// OFFSET: LEGO1 0x10003b80
float MxVector3::DotImpl(float *p_a, float *p_b) const
{
  return p_a[0] * p_b[0] + p_a[2] * p_b[2] + p_a[1] * p_b[1];
}

// OFFSET: LEGO1 0x10003ba0
void MxVector3::EqualsImpl(float *p_data)
{
  float *vec = m_data;
  vec[0] = p_data[0];
  vec[1] = p_data[1];
  vec[2] = p_data[2];
}

// OFFSET: LEGO1 0x10003bc0
void MxVector3::Clear()
{
  float *vec = m_data;
  vec[0] = 0.0f;
  vec[1] = 0.0f;
  vec[2] = 0.0f;
}

// OFFSET: LEGO1 0x10003bd0
float MxVector3::LenSquared() const
{
  return m_data[1] * m_data[1] + m_data[0] * m_data[0] + m_data[2] * m_data[2];
}

// OFFSET: LEGO1 0x10002270
void MxVector3::EqualsCrossImpl(float* p_a, float* p_b)
{
  m_data[0] = p_a[1] * p_b[2] - p_a[2] * p_b[1];
  m_data[1] = p_a[2] * p_b[0] - p_a[0] * p_b[2];
  m_data[2] = p_a[0] * p_b[1] - p_a[1] * p_b[0];
}

// OFFSET: LEGO1 0x10002300
void MxVector3::EqualsCross(float *p_a, MxVector3 *p_b)
{
  EqualsCrossImpl(p_a, p_b->m_data);
}

// OFFSET: LEGO1 0x100022e0
void MxVector3::EqualsCross(MxVector3 *p_a, float *p_b)
{
  EqualsCrossImpl(p_a->m_data, p_b);
}

// OFFSET: LEGO1 0x100022c0
void MxVector3::EqualsCross(MxVector3 *p_a, MxVector3 *p_b)
{
  EqualsCrossImpl(p_a->m_data, p_b->m_data);
}

// OFFSET: LEGO1 0x10003bf0
void MxVector3::EqualsScalar(float *p_value)
{
  m_data[0] = *p_value;
  m_data[1] = *p_value;
  m_data[2] = *p_value;
}

// OFFSET: LEGO1 0x100028b0
void MxVector4::AddScalarImpl(float p_value)
{
  m_data[0] += p_value;
  m_data[1] += p_value;
  m_data[2] += p_value;
  m_data[3] += p_value;
}

// OFFSET: LEGO1 0x10002870
void MxVector4::AddVectorImpl(float *p_value)
{
  m_data[0] += p_value[0];
  m_data[1] += p_value[1];
  m_data[2] += p_value[2];
  m_data[3] += p_value[3];
}

// OFFSET: LEGO1 0x100028f0
void MxVector4::SubVectorImpl(float *p_value)
{
  m_data[0] -= p_value[0];
  m_data[1] -= p_value[1];
  m_data[2] -= p_value[2];
  m_data[3] -= p_value[3];
}

// OFFSET: LEGO1 0x10002970
void MxVector4::MullScalarImpl(float *p_value)
{
  m_data[0] *= *p_value;
  m_data[1] *= *p_value;
  m_data[2] *= *p_value;
  m_data[3] *= *p_value;
}

// OFFSET: LEGO1 0x10002930
void MxVector4::MullVectorImpl(float *p_value)
{
  m_data[0] *= p_value[0];
  m_data[1] *= p_value[1];
  m_data[2] *= p_value[2];
  m_data[3] *= p_value[3];
}

// OFFSET: LEGO1 0x100029b0
void MxVector4::DivScalarImpl(float *p_value)
{
  m_data[0] /= *p_value;
  m_data[1] /= *p_value;
  m_data[2] /= *p_value;
  m_data[3] /= *p_value;
}

// OFFSET: LEGO1 0x100029f0
float MxVector4::DotImpl(float *p_a, float *p_b) const
{
  return
    p_a[0] * p_b[0] + p_a[2] * p_b[2] +
    (p_a[1] * p_b[1] + p_a[3] * p_b[3]);
}

// OFFSET: LEGO1 0x10002a20
void MxVector4::EqualsImpl(float *p_data)
{
  float *vec = m_data;
  vec[0] = p_data[0];
  vec[1] = p_data[1];
  vec[2] = p_data[2];
  vec[3] = p_data[3];
}

// OFFSET: LEGO1 0x10002b00
void MxVector4::Clear()
{
  float *vec = m_data;
  vec[0] = 0.0f;
  vec[1] = 0.0f;
  vec[2] = 0.0f;
  vec[3] = 0.0f;
}

// OFFSET: LEGO1 0x10002b20
float MxVector4::LenSquared() const
{
  return m_data[1] * m_data[1] + m_data[0] * m_data[0] + 
    m_data[2] * m_data[2] + m_data[3] * m_data[3];
}

// OFFSET: LEGO1 0x10002b40
void MxVector4::EqualsScalar(float *p_value)
{
  m_data[0] = *p_value;
  m_data[1] = *p_value;
  m_data[2] = *p_value;
  m_data[3] = *p_value;
}

// OFFSET: LEGO1 0x10002ae0
void MxVector4::SetMatrixProduct(MxVector4 *p_a, float *p_b)
{
  SetMatrixProductImpl(p_a->m_data, p_b);
}

// OFFSET: LEGO1 0x10002a40
void MxVector4::SetMatrixProductImpl(float *p_vec, float *p_mat)
{
  m_data[0] =
      p_vec[0] * p_mat[0] + p_vec[1] * p_mat[4] +
      p_vec[2] * p_mat[8] + p_vec[3] * p_mat[12];
  m_data[1] =
      p_vec[0] * p_mat[1] + p_vec[1] * p_mat[5] +
      p_vec[2] * p_mat[9] + p_vec[4] * p_mat[13];
  m_data[2] =
      p_vec[0] * p_mat[2] + p_vec[1] * p_mat[6] +
      p_vec[2] * p_mat[10] + p_vec[4] * p_mat[14];
  m_data[3] =
      p_vec[0] * p_mat[3] + p_vec[1] * p_mat[7] +
      p_vec[2] * p_mat[11] + p_vec[4] * p_mat[15];
}

// Note close yet, included because I'm at least confident I know what operation
// it's trying to do.
// OFFSET: LEGO1 0x10002b70 STUB
MxResult MxVector4::NormalizeQuaternion()
{
  float *v = m_data;
  float magnitude = v[1] * v[1] + v[2] * v[2] + v[0] * v[0];
  if (magnitude > 0.0f)
  {
    float theta = v[3] * 0.5f;
    v[3] = cos(theta);
    float frac = sin(theta);
    magnitude = frac / sqrt(magnitude);
    v[0] *= magnitude;
    v[1] *= magnitude;
    v[2] *= magnitude;
    return SUCCESS;
  }
  return FAILURE;
}

// OFFSET: LEGO1 0x10002bf0
void MxVector4::UnknownQuaternionOp(MxVector4 *p_a, MxVector4 *p_b)
{
  MxFloat *bDat = p_b->m_data;
  MxFloat *aDat = p_a->m_data;

  this->m_data[3] = aDat[3] * bDat[3] - (bDat[0] * aDat[0] + aDat[2] *bDat[2] + aDat[1] * aDat[1]);
  this->m_data[0] = bDat[2] * aDat[1] - bDat[1] * aDat[2];
  this->m_data[1] = aDat[2] * bDat[0] - bDat[2] * aDat[0];
  this->m_data[2] = bDat[1] * aDat[0] - aDat[1] * bDat[0];


  m_data[0] = p_b->m_data[3] * p_a->m_data[0] + p_a->m_data[3] * p_b->m_data[0] + m_data[0];
  m_data[1] = p_b->m_data[1] * p_a->m_data[3] + p_a->m_data[1] * p_b->m_data[3] + m_data[1];
  m_data[2] = p_b->m_data[2] * p_a->m_data[3] + p_a->m_data[2] * p_b->m_data[3] + m_data[2];
}
