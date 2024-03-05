#ifndef __LEGOVERTEX_H
#define __LEGOVERTEX_H

#include "misc/legotypes.h"

class LegoStorage;

// SIZE 0x0c
class LegoVertex {
public:
	LegoVertex();
	LegoFloat GetCoordinate(LegoU32 p_i) { return m_coordinates[p_i]; }
	void SetCoordinate(LegoU32 p_i, LegoFloat p_coordinate) { m_coordinates[p_i] = p_coordinate; }
	LegoFloat GetX() { return m_coordinates[0]; }
	void SetX(LegoFloat p_x) { m_coordinates[0] = p_x; }
	LegoFloat GetY() { return m_coordinates[1]; }
	void SetY(LegoFloat p_y) { m_coordinates[1] = p_y; }
	LegoFloat GetZ() { return m_coordinates[2]; }
	void SetZ(LegoFloat p_z) { m_coordinates[2] = p_z; }
	LegoBool IsOrigin() { return m_coordinates[0] == 0.0 && m_coordinates[1] == 0.0 && m_coordinates[2] == 0.0; }
	LegoResult Read(LegoStorage* p_storage);

	LegoFloat& operator[](int i) { return m_coordinates[i]; }
	LegoFloat operator[](int i) const { return m_coordinates[i]; }

protected:
	LegoFloat m_coordinates[3]; // 0x00
};

#endif // __LEGOVERTEX_H
