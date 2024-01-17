#ifndef _tglVector_h
#define _tglVector_h

#include "math.h" // sin() in RotateAroundY()

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

typedef float FloatMatrix4[4][4];

} // namespace Tgl

#endif /* _tglVector_h */
