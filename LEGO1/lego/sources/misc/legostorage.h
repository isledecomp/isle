#ifndef __LEGOSTORAGE_H
#define __LEGOSTORAGE_H

#include "legotypes.h"
#include "mxgeometry/mxgeometry3d.h"
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
	virtual ~LegoStorage() {}

	virtual LegoResult Read(void* p_buffer, LegoU32 p_size) = 0;        // vtable+0x04
	virtual LegoResult Write(const void* p_buffer, LegoU32 p_size) = 0; // vtable+0x08
	virtual LegoResult GetPosition(LegoU32& p_position) = 0;            // vtable+0x0c
	virtual LegoResult SetPosition(LegoU32 p_position) = 0;             // vtable+0x10

	// FUNCTION: LEGO1 0x10045ae0
	virtual LegoBool IsWriteMode() { return m_mode == c_write; } // vtable+0x14

	// FUNCTION: LEGO1 0x10045af0
	virtual LegoBool IsReadMode() { return m_mode == c_read; } // vtable+0x18

	// FUNCTION: BETA10 0x10017c80
	LegoStorage* WriteString(const char* p_data)
	{
		LegoS16 length = strlen(p_data);
		WriteS16(length);
		Write(p_data, length);
		return this;
	}

	// FUNCTION: BETA10 0x1004b0d0
	LegoStorage* WriteU8(LegoU8 p_data)
	{
		Write(&p_data, sizeof(p_data));
		return this;
	}

	// FUNCTION: BETA10 0x10017ce0
	LegoStorage* WriteS16(LegoS16 p_data)
	{
		Write(&p_data, sizeof(p_data));
		return this;
	}

	// FUNCTION: BETA10 0x1004b110
	LegoStorage* WriteU16(LegoU16 p_data)
	{
		Write(&p_data, sizeof(p_data));
		return this;
	}

	// TODO: Type might be different (LegoS32). MxS32 is incompatible with LegoS32.
	// FUNCTION: BETA10 0x10088540
	LegoStorage* WriteS32(MxS32 p_data)
	{
		Write(&p_data, sizeof(p_data));
		return this;
	}

	// TODO: Type might be different (LegoU32). MxU32 is incompatible with LegoU32.
	// FUNCTION: BETA10 0x1004b150
	LegoStorage* WriteU32(MxU32 p_data)
	{
		Write(&p_data, sizeof(p_data));
		return this;
	}

	LegoStorage* WriteFloat(LegoFloat p_data)
	{
		Write(&p_data, sizeof(p_data));
		return this;
	}

	// FUNCTION: LEGO1 0x100343d0
	LegoStorage* WriteVector(Mx3DPointFloat p_data)
	{
		WriteFloat(p_data[0]);
		WriteFloat(p_data[1]);
		WriteFloat(p_data[2]);
		return this;
	}

	// FUNCTION: LEGO1 0x10006030
	// FUNCTION: BETA10 0x10017bb0
	LegoStorage* WriteMxString(MxString p_data)
	{
		WriteString(p_data.GetData());
		return this;
	}

	LegoStorage* ReadString(char* p_data)
	{
		LegoS16 length;
		ReadS16(length);
		Read(p_data, length);
		p_data[length] = '\0';
		return this;
	}

	// FUNCTION: BETA10 0x1004b190
	LegoStorage* ReadU8(LegoU8& p_data)
	{
		Read(&p_data, sizeof(p_data));
		return this;
	}

	// FUNCTION: BETA10 0x10024680
	LegoStorage* ReadS16(LegoS16& p_data)
	{
		Read(&p_data, sizeof(p_data));
		return this;
	}

	// FUNCTION: BETA10 0x1004b1d0
	LegoStorage* ReadU16(LegoU16& p_data)
	{
		Read(&p_data, sizeof(p_data));
		return this;
	}

	// TODO: Type might be different (LegoS32). MxS32 is incompatible with LegoS32.
	// FUNCTION: BETA10 0x10088580
	LegoStorage* ReadS32(MxS32& p_data)
	{
		Read(&p_data, sizeof(p_data));
		return this;
	}

	// TODO: Type might be different (LegoU32). MxU32 is incompatible with LegoU32.
	// FUNCTION: BETA10 0x1004b210
	LegoStorage* ReadU32(MxU32& p_data)
	{
		Read(&p_data, sizeof(p_data));
		return this;
	}

	LegoStorage* ReadFloat(LegoFloat& p_data)
	{
		Read(&p_data, sizeof(p_data));
		return this;
	}

	// FUNCTION: LEGO1 0x10034430
	LegoStorage* ReadVector(Mx3DPointFloat& p_data)
	{
		ReadFloat(p_data[0]);
		ReadFloat(p_data[1]);
		ReadFloat(p_data[2]);
		return this;
	}

	// FUNCTION: LEGO1 0x10034470
	LegoStorage* ReadMxString(MxString& p_data)
	{
		LegoS16 length;
		ReadS16(length);

		char* text = new char[length + 1];
		Read(text, length);

		text[length] = '\0';
		p_data = text;
		delete[] text;
		return this;
	}

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
	LegoResult Read(void* p_buffer, LegoU32 p_size) override;        // vtable+0x04
	LegoResult Write(const void* p_buffer, LegoU32 p_size) override; // vtable+0x08

	// FUNCTION: LEGO1 0x100994a0
	LegoResult GetPosition(LegoU32& p_position) override // vtable+0x0c
	{
		p_position = m_position;
		return SUCCESS;
	}

	// FUNCTION: LEGO1 0x100994b0
	LegoResult SetPosition(LegoU32 p_position) override // vtable+0x10
	{
		m_position = p_position;
		return SUCCESS;
	}

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
	~LegoFile() override;

	LegoResult Read(void* p_buffer, LegoU32 p_size) override;        // vtable+0x04
	LegoResult Write(const void* p_buffer, LegoU32 p_size) override; // vtable+0x08
	LegoResult GetPosition(LegoU32& p_position) override;            // vtable+0x0c
	LegoResult SetPosition(LegoU32 p_position) override;             // vtable+0x10
	LegoResult Open(const char* p_name, LegoU32 p_mode);

	// SYNTHETIC: LEGO1 0x10099230
	// LegoFile::`scalar deleting destructor'

protected:
	FILE* m_file; // 0x08
};

#endif // __LEGOSTORAGE_H
