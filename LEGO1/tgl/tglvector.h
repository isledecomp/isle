#ifndef TGLVECTOR_H
#define TGLVECTOR_H

#include "math.h" // ??? sin() in  RotateAroundY()

#include <stddef.h> // offsetof()

namespace Tgl
{

namespace Constant
{
const float Pi = 3.14159265358979323846;
};

inline float DegreesToRadians(float degrees)
{
	return Constant::Pi * (degrees / 180.0);
}

inline float RadiansToDegrees(float radians)
{
	return (radians / Constant::Pi) * 180.0;
}

//////////////////////////////////////////////////////////////////////////////
//
// Array<T, N>

template <class T, int N>
class Array {
public:
	Array() {}
	Array(const Array& rArray) { *this = rArray; }
	~Array() {}

	const T& operator[](int i) const { return m_elements[i]; };
	T& operator[](int i) { return m_elements[i]; };

	Array<T, N>& operator=(const Array<T, N>&);
	void operator+=(const Array<T, N>&);

protected:
	T m_elements[N];
};

//////////////////////////////////////////////////////////////////////////////
//
// Array<T, N> implementation

template <class T, int N>
inline Array<T, N>& Array<T, N>::operator=(const Array<T, N>& rArray)
{
	int i;

	for (i = 0; i < N; i++) {
		m_elements[i] = rArray.m_elements[i];
	}

	return *this;
}

template <class T, int N>
inline void Array<T, N>::operator+=(const Array<T, N>& rArray)
{
	int i;

	for (i = 0; i < N; i++) {
		m_elements[i] += rArray.m_elements[i];
	}
}

//////////////////////////////////////////////////////////////////////////////
//
// FloatMatrix4

class FloatMatrix4 : public Array<Array<float, 4>, 4> {
public:
	FloatMatrix4() {}
	FloatMatrix4(const FloatMatrix4& rMatrix) { *this = rMatrix; }
	FloatMatrix4(const FloatMatrix4&, const FloatMatrix4&);

	void operator*=(const FloatMatrix4&);
};

//////////////////////////////////////////////////////////////////////////////
//
// FloatMatrix4 implementation

inline FloatMatrix4::FloatMatrix4(const FloatMatrix4& rMatrix1, const FloatMatrix4& rMatrix2)
{
	for (int row = 0; row < 4; row++) {
		for (int column = 0; column < 4; column++) {
			float element = 0;

			for (int i = 0; i < 4; i++) {
				element += rMatrix1[row][i] * rMatrix2[i][column];
			}

			m_elements[row][column] = element;
		}
	}
}

inline void FloatMatrix4::operator*=(const FloatMatrix4& rMatrix)
{
	FloatMatrix4 temp(*this, rMatrix);

	// *this = FloatMatrix4(*this, rMatrix);
	*this = temp;
}

//////////////////////////////////////////////////////////////////////////////
//
// Transformation matrices

class Translation : public FloatMatrix4 {
public:
	Translation(const float[3]);
	Translation(float x, float y, float z);

protected:
	void Init(float x, float y, float z);
};

class Scale : public FloatMatrix4 {
public:
	Scale(const float[3]);
	Scale(float x, float y, float z);
	Scale(float);

protected:
	void Init(float x, float y, float z);
};

class RotationX : public FloatMatrix4 {
public:
	RotationX(float radians);
};

class RotationY : public FloatMatrix4 {
public:
	RotationY(float radians);
};

//////////////////////////////////////////////////////////////////////////////
//
// Transformation matrices implementation

inline Translation::Translation(const float vector[3])
{
	Init(vector[0], vector[1], vector[2]);
}

inline Translation::Translation(float x, float y, float z)
{
	Init(x, y, z);
}

inline void Translation::Init(float x, float y, float z)
{
	m_elements[0][0] = 1;
	m_elements[0][1] = 0;
	m_elements[0][2] = 0;
	m_elements[0][3] = 0;

	m_elements[1][0] = 0;
	m_elements[1][1] = 1;
	m_elements[1][2] = 0;
	m_elements[1][3] = 0;

	m_elements[2][0] = 0;
	m_elements[2][1] = 0;
	m_elements[2][2] = 1;
	m_elements[2][3] = 0;

	m_elements[3][0] = x;
	m_elements[3][1] = y;
	m_elements[3][2] = z;
	m_elements[3][3] = 1;
}

inline Scale::Scale(const float vector[3])
{
	Init(vector[0], vector[1], vector[2]);
}

inline Scale::Scale(float x, float y, float z)
{
	Init(x, y, z);
}

inline Scale::Scale(float scale)
{
	Init(scale, scale, scale);
}

inline void Scale::Init(float x, float y, float z)
{
	m_elements[0][0] = x;
	m_elements[0][1] = 0;
	m_elements[0][2] = 0;
	m_elements[0][3] = 0;

	m_elements[1][0] = 0;
	m_elements[1][1] = y;
	m_elements[1][2] = 0;
	m_elements[1][3] = 0;

	m_elements[2][0] = 0;
	m_elements[2][1] = 0;
	m_elements[2][2] = z;
	m_elements[2][3] = 0;

	m_elements[3][0] = 0;
	m_elements[3][1] = 0;
	m_elements[3][2] = 0;
	m_elements[3][3] = 1;
}

inline RotationX::RotationX(float radians)
{
	float cosRadians = cos(radians);
	float sinRadians = sin(radians);

	m_elements[0][0] = 1;
	m_elements[0][1] = 0;
	m_elements[0][2] = 0;
	m_elements[0][3] = 0;

	m_elements[1][0] = 0;
	m_elements[1][1] = cosRadians;
	m_elements[1][2] = -sinRadians;
	m_elements[1][3] = 0;

	m_elements[2][0] = 0;
	m_elements[2][1] = sinRadians;
	m_elements[2][2] = cosRadians;
	m_elements[2][3] = 0;

	m_elements[3][0] = 0;
	m_elements[3][1] = 0;
	m_elements[3][2] = 0;
	m_elements[3][3] = 1;
}

inline RotationY::RotationY(float radians)
{
	float cosRadians = cos(radians);
	float sinRadians = sin(radians);

	m_elements[0][0] = cosRadians;
	m_elements[0][1] = 0;
	m_elements[0][2] = sinRadians;
	m_elements[0][3] = 0;

	m_elements[1][0] = 0;
	m_elements[1][1] = 1;
	m_elements[1][2] = 0;
	m_elements[1][3] = 0;

	m_elements[2][0] = -sinRadians;
	m_elements[2][1] = 0;
	m_elements[2][2] = cosRadians;
	m_elements[2][3] = 0;

	m_elements[3][0] = 0;
	m_elements[3][1] = 0;
	m_elements[3][2] = 0;
	m_elements[3][3] = 1;
}

//////////////////////////////////////////////////////////////////////////////

} // namespace Tgl

#endif // TLGVECTOR_H
