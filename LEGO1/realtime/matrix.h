#ifndef MATRIX_H
#define MATRIX_H

#include "vector.h"

// Note: virtual function overloads appear in the virtual table
// in reverse order of appearance.

struct UnknownMatrixType {
	float m_data[4][4];
};

// VTABLE: LEGO1 0x100d4350
// VTABLE: BETA10 0x101b8340
// SIZE 0x08
class Matrix4 {
protected:
	float (*m_data)[4];

public:
	// FUNCTION: LEGO1 0x10004500
	// FUNCTION: BETA10 0x1000fc70
	Matrix4(float (*p_data)[4]) { SetData(p_data); }

	inline virtual void Equals(float (*p_data)[4]);                                           // vtable+0x04
	inline virtual void Equals(const Matrix4& p_matrix);                                      // vtable+0x00
	inline virtual void SetData(float (*p_data)[4]);                                          // vtable+0x0c
	inline virtual void SetData(UnknownMatrixType& p_matrix);                                 // vtable+0x08
	inline virtual float (*GetData())[4];                                                     // vtable+0x14
	inline virtual float (*GetData() const)[4];                                               // vtable+0x10
	inline virtual float* Element(int p_row, int p_col);                                      // vtable+0x1c
	inline virtual const float* Element(int p_row, int p_col) const;                          // vtable+0x18
	inline virtual void Clear();                                                              // vtable+0x20
	inline virtual void SetIdentity();                                                        // vtable+0x24
	inline virtual void operator=(const Matrix4& p_matrix);                                   // vtable+0x28
	inline virtual Matrix4& operator+=(float (*p_data)[4]);                                   // vtable+0x2c
	inline virtual void TranslateBy(const float& p_x, const float& p_y, const float& p_z);    // vtable+0x30
	inline virtual void SetTranslation(const float& p_x, const float& p_y, const float& p_z); // vtable+0x34
	inline virtual void Product(float (*p_a)[4], float (*p_b)[4]);                            // vtable+0x3c
	inline virtual void Product(const Matrix4& p_a, const Matrix4& p_b);                      // vtable+0x38
	inline virtual void ToQuaternion(Vector4& p_resultQuat);                                  // vtable+0x40
	inline virtual int FromQuaternion(const Vector4& p_vec);                                  // vtable+0x44

	inline void Scale(const float& p_x, const float& p_y, const float& p_z);
	inline void RotateX(const float& p_angle);
	inline void RotateY(const float& p_angle);
	inline void RotateZ(const float& p_angle);
	inline int BETA_1005a590(Matrix4& p_mat);
	inline void Swap(int p_d1, int p_d2);

	// FUNCTION: BETA10 0x1001c670
	float* operator[](int idx) { return m_data[idx]; }

	// FUNCTION: BETA10 0x10017780
	const float* operator[](int idx) const { return m_data[idx]; }
};

#ifdef COMPAT_MODE
#include "matrix4d.inl.h"
#endif

#endif // MATRIX_H
