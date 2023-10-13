#ifndef MXMATRIX_H
#define MXMATRIX_H

#include "mxvector.h"

// VTABLE 0x100d4350
// SIZE 0x8
class MxMatrix
{
public:
  inline MxMatrix(float *p_data) : m_data(p_data) {}

  // vtable + 0x00
  virtual void EqualsMxMatrix(const MxMatrix *p_other);
  virtual void EqualsMatrixData(const float *p_matrix);
  virtual void SetData(float *p_data);
  virtual void AnotherSetData(float *p_data);

  // vtable + 0x10
  virtual float *GetData();
  virtual const float *GetData() const;
  virtual float *Element(int p_row, int p_col);
  virtual const float *Element(int p_row, int p_col) const;

  // vtable + 0x20
  virtual void Clear();
  virtual void SetIdentity();
  virtual void operator=(const MxMatrix& p_other);
  virtual MxMatrix *operator+=(const float *p_matrix);

  // vtable + 0x30
  virtual void TranslateBy(const float *p_x, const float *p_y, const float *p_z);
  virtual void SetTranslation(const float *p_x, const float *p_y, const float *p_z);
  virtual void EqualsMxProduct(const MxMatrix *p_a, const MxMatrix *p_b);
  virtual void EqualsDataProduct(const float *p_a, const float *p_b);

  // vtable + 0x40
  virtual void ToQuaternion(MxVector4 *p_resultQuat);
  virtual MxResult FUN_10002710(const MxVector3 *p_vec);

private:
  float *m_data;
};

// VTABLE 0x100d4300
// SIZE 0x48
class MxMatrixData : public MxMatrix
{
public:
  inline MxMatrixData() : MxMatrix(e) {}

  // No idea why there's another equals. Maybe to some other type like the
  // DirectX Retained Mode Matrix type which is also a float* alias?
  // vtable + 0x44
  virtual void operator=(const MxMatrixData& p_other);

  // Alias an easy way to access the translation part of the matrix, because
  // various members / other functions benefit from the clarity.
  union
  {
    float e[16];
    struct
    {
      float _[12];
      float x, y, z, w;
    };
  };
};

#endif // MXMATRIX_H