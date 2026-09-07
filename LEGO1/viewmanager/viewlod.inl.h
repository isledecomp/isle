#ifndef VIEWLOD_INL_H
#define VIEWLOD_INL_H

#include "viewlod.h"

// FUNCTION: LEGO1 0x100a6f30
// FUNCTION: BETA10 0x10174db0
inline double ViewLOD::AveragePolyArea() const
{
	return 2 * 3.14159 * 10.0 / NumPolys();
}

// FUNCTION: LEGO1 0x100a6f50
// FUNCTION: BETA10 0x10174de0
inline int ViewLOD::NVerts() const
{
	return NumPolys() * 2;
}

#endif // VIEWLOD_INL_H
