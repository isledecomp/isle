#ifndef __LEGOSTORAGE_H
#define __LEGOSTORAGE_H

#include "legotypes.h"
#include "mxstring.h"

#include <stdio.h>

// VTABLE: LEGO1 0x100d7d80
// SIZE 0x08
class LegoStorage {
public:
	enum OpenFlags {
		c_read = 1,
		c_write = 2,
		c_text = 4
	};

	LegoStorage() : m_mode(0) {}

	// FUNCTION: LEGO1 0x10045ad0
	virtual ~LegoStorage(){};

	virtual LegoResult Read(void* p_buffer, LegoU32 p_size) = 0;
	virtual LegoResult Write(const void* p_buffer, LegoU32 p_size) = 0;
	virtual LegoResult GetPosition(LegoU32& p_position) = 0;
	virtual LegoResult SetPosition(LegoU32 p_position) = 0;

	// FUNCTION: LEGO1 0x10045ae0
	virtual LegoBool IsWriteMode() { return m_mode == c_write; }

	// FUNCTION: LEGO1 0x10045af0
	virtual LegoBool IsReadMode() { return m_mode == c_read; }

	// SYNTHETIC: LEGO1 0x10045b00
	// LegoStorage::`scalar deleting destructor'

protected:
	LegoU8 m_mode; // 0x04
};

// VTABLE: LEGO1 0x100db710
// SIZE 0x10
class LegoMemory : public LegoStorage {
public:
	LegoMemory(void* p_buffer);
	virtual LegoResult Read(void* p_buffer, LegoU32 p_size);
	virtual LegoResult Write(const void* p_buffer, LegoU32 p_size);
	virtual LegoResult GetPosition(LegoU32& p_position);
	virtual LegoResult SetPosition(LegoU32 p_position);

	// SYNTHETIC: LEGO1 0x10045a80
	// LegoMemory::~LegoMemory

	// SYNTHETIC: LEGO1 0x100990f0
	// LegoMemory::`scalar deleting destructor'

protected:
	LegoU8* m_buffer;   // 0x04
	LegoU32 m_position; // 0x08
};

// VTABLE: LEGO1 0x100db730
// SIZE 0x0c
class LegoFile : public LegoStorage {
public:
	LegoFile();
	virtual ~LegoFile();
	virtual LegoResult Read(void* p_buffer, LegoU32 p_size);
	virtual LegoResult Write(const void* p_buffer, LegoU32 p_size);
	virtual LegoResult GetPosition(LegoU32& p_position);
	virtual LegoResult SetPosition(LegoU32 p_position);
	LegoResult Open(const char* p_name, LegoU32 p_mode);

	// FUNCTION: LEGO1 0x10006030
	LegoStorage* FUN_10006030(MxString p_str)
	{
		const char* data = p_str.GetData();
		LegoU32 fullLength = strlen(data);

		LegoU16 limitedLength = fullLength;
		Write(&limitedLength, sizeof(limitedLength));
		Write((char*) data, (LegoS16) fullLength);

		return this;
	}

	// SYNTHETIC: LEGO1 0x10099230
	// LegoFile::`scalar deleting destructor'

protected:
	FILE* m_file; // 0x08
};

#endif // __LEGOSTORAGE_H
