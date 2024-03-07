#ifndef __LEGOCOLOR_H
#define __LEGOCOLOR_H

#include "legotypes.h"

class LegoStorage;

// SIZE 0x03
class LegoColor {
public:
	LegoColor() { m_red = m_green = m_blue = 0; }
	LegoU8 GetRed() { return m_red; }
	void SetRed(LegoU8 p_red) { m_red = p_red; }
	LegoU8 GetGreen() { return m_green; }
	void SetGreen(LegoU8 p_green) { m_green = p_green; }
	LegoU8 GetBlue() { return m_blue; }
	void SetBlue(LegoU8 p_blue) { m_blue = p_blue; }
	LegoResult Read(LegoStorage* p_storage);

protected:
	LegoU8 m_red;   // 0x00
	LegoU8 m_green; // 0x01
	LegoU8 m_blue;  // 0x02
};

#endif // __LEGOCOLOR_H
