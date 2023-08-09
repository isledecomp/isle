#ifndef MXVECTOR_H
#define MXVECTOR_H

#include "mxtypes.h"

// VTABLE 0x100d4288
// SIZE 0x8
class MxVector2
{
public:
  // OFFSET: LEGO1 0x1000c0f0
  inline MxVector2(float* p_data) { this->SetData(p_data); }

  // vtable + 0x00 (no virtual destructor)
  virtual void AddScalarImpl(float p_value) = 0;
  virtual void AddVectorImpl(float *p_value) = 0;
  virtual void SubVectorImpl(float *p_value) = 0;
  virtual void MullScalarImpl(float *p_value) = 0;

  // vtable + 0x10
  virtual void MullVectorImpl(float *p_value) = 0;
  virtual void DivScalarImpl(float *p_value) = 0;
  virtual float DotImpl(float *p_a, float *p_b) const = 0;

  // OFFSET: LEGO1 0x10002060
  virtual void SetData(float *p_data) { this->m_data = p_data; }

  // vtable + 0x20
  virtual void EqualsImpl(float *p_data) = 0;
  virtual const float *GetData() const;
  virtual float *GetData();
  virtual void Clear() = 0;

  // vtable + 0x30
  virtual float Dot(MxVector2 *p_a, float *p_b) const;
  virtual float Dot(float *p_a, MxVector2 *p_b) const;
  virtual float Dot(MxVector2 *p_a, MxVector2 *p_b) const;
  virtual float Dot(float *p_a, float *p_b) const;

  // vtable + 0x40
  virtual float LenSquared() const = 0;
  virtual MxResult Unitize();

  // vtable + 0x48
  virtual void AddVector(MxVector2 *p_other);
  virtual void AddVector(float *p_other);
  virtual void AddScalar(float p_value);

  // vtable + 0x54
  virtual void SubVector(MxVector2 *p_other);
  virtual void SubVector(float *p_other);

  // vtable + 0x5C
  virtual void MullScalar(float *p_value);
  virtual void MullVector(MxVector2 *p_other);
  virtual void MullVector(float *p_other);
  virtual void DivScalar(float *p_value);

  // vtable + 0x6C
  virtual void SetVector(MxVector2 *other);
  virtual void SetVector(float *other);

  inline float& operator[](size_t idx) { return m_data[idx]; }
  inline const float operator[](size_t idx) const { return m_data[idx]; }
protected:
  float *m_data;
};

// VTABLE 0x100d4518
// SIZE 0x8
class MxVector3 : public MxVector2
{
public:
  inline MxVector3(float* p_data) : MxVector2(p_data) {}

  void AddScalarImpl(float p_value);

  void AddVectorImpl(float *p_value);

  void SubVectorImpl(float *p_value);
  void MullScalarImpl(float *p_value);
  void MullVectorImpl(float *p_value);
  void DivScalarImpl(float *p_value);
  float DotImpl(float *p_a, float *p_b) const;

  void EqualsImpl(float *p_data);

  void Clear();

  float LenSquared() const;

  // vtable + 0x74
  virtual void EqualsCrossImpl(float* p_a, float* p_b);
  virtual void EqualsCross(float *p_a, MxVector3 *p_b);
  virtual void EqualsCross(MxVector3 *p_a, float *p_b);
  virtual void EqualsCross(MxVector3 *p_a, MxVector3 *p_b);
  virtual void EqualsScalar(float *p_value);
};

// VTABLE 0x100d45a0
// SIZE 0x8
class MxVector4 : public MxVector3
{
public:
  inline MxVector4(float* p_data) : MxVector3(p_data) {}

  void AddScalarImpl(float p_value);

  void AddVectorImpl(float *p_value);

  void SubVectorImpl(float *p_value);
  void MullScalarImpl(float *p_value);
  void MullVectorImpl(float *p_value);
  void DivScalarImpl(float *p_value);
  float DotImpl(float *p_a, float *p_b) const;

  void EqualsImpl(float *p_data);

  void Clear();

  float LenSquared() const;

  void EqualsScalar(float *p_value);

  // vtable + 0x84
  virtual void unk1(MxVector4 *p_a, float *p_b);
  virtual void SetMatrixProduct(float *p_vec, float *p_mat);
  virtual MxResult NormalizeQuaternion();
  virtual void UnknownQuaternionOp(MxVector4 *p_a, MxVector4 *p_b);
};

// VTABLE 0x100d4488
// SIZE 0x14
class MxVector3Data : public MxVector3
{
public:
  inline MxVector3Data() : MxVector3(&x) {}
  inline MxVector3Data(float p_x, float p_y, float p_z)
    : MxVector3(&x)
    , x(p_x), y(p_y), z(p_z)
    {}
  float x, y, z;
};

// VTABLE 0x100d41e8
// SIZE 0x18
class MxVector4Data : public MxVector4
{
public:
  inline MxVector4Data() : MxVector4(&x) {}
  float x, y, z, w;
};

#endif // MXVECTOR_H