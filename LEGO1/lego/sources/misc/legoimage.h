#ifndef __LEGOIMAGE_H
#define __LEGOIMAGE_H

#include "legotypes.h"

class LegoStorage;

// SIZE 0x03
class LegoPaletteEntry {
public:
	LegoPaletteEntry();
	// LegoPaletteEntry(LegoU8 p_red, LegoU8 p_green, LegoU8 p_blue);
	LegoU8 GetRed() { return m_red; }
	void SetRed(LegoU8 p_red) { m_red = p_red; }
	LegoU8 GetGreen() { return m_green; }
	void SetGreen(LegoU8 p_green) { m_green = p_green; }
	LegoU8 GetBlue() { return m_blue; }
	void SetBlue(LegoU8 p_blue) { m_blue = p_blue; }
	LegoResult Read(LegoStorage* p_storage);
	LegoResult Write(LegoStorage* p_storage);

protected:
	LegoU8 m_red;   // 0x00
	LegoU8 m_green; // 0x01
	LegoU8 m_blue;  // 0x02
};

// 0x310
class LegoImage {
public:
	LegoImage();
	LegoImage(LegoU32 p_width, LegoU32 p_height);
	~LegoImage();
	LegoU32 GetWidth() { return m_width; }
	void SetWidth(LegoU32 p_width) { m_width = p_width; }
	LegoU32 GetHeight() { return m_height; }
	void SetHeight(LegoU32 p_height) { m_height = p_height; }
	LegoPaletteEntry* GetPalette() { return m_palette; }
	LegoPaletteEntry& GetPaletteEntry(LegoU32 p_i) { return m_palette[p_i]; }
	void SetPaletteEntry(LegoU32 p_i, LegoPaletteEntry& p_paletteEntry) { m_palette[p_i] = p_paletteEntry; }
	LegoU8* GetBits() { return m_bits; }
	void SetBits(LegoU8* p_bits) { m_bits = p_bits; }
	LegoResult Read(LegoStorage* p_storage, LegoU32 p_square);
	LegoResult Write(LegoStorage* p_storage);

protected:
	LegoU32 m_width;                 // 0x00
	LegoU32 m_height;                // 0x04
	LegoU32 m_count;                 // 0x08
	LegoPaletteEntry m_palette[256]; // 0x0c
	LegoU8* m_bits;                  // 0x30c
};

#endif // __LEGOIMAGE_H
