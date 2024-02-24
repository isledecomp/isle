#include "legostorage.h"

#include "decomp.h"

#include <memory.h>
#include <string.h>

DECOMP_SIZE_ASSERT(LegoStorage, 0x08);
DECOMP_SIZE_ASSERT(LegoMemory, 0x10);
DECOMP_SIZE_ASSERT(LegoFile, 0x0c);

// FUNCTION: LEGO1 0x10099080
LegoMemory::LegoMemory(void* p_buffer) : LegoStorage()
{
	m_buffer = (LegoU8*) p_buffer;
	m_position = 0;
}

// FUNCTION: LEGO1 0x10099160
LegoResult LegoMemory::Read(void* p_buffer, LegoU32 p_size)
{
	memcpy(p_buffer, m_buffer + m_position, p_size);
	m_position += p_size;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10099190
LegoResult LegoMemory::Write(const void* p_buffer, LegoU32 p_size)
{
	memcpy(m_buffer + m_position, p_buffer, p_size);
	m_position += p_size;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100991c0
LegoFile::LegoFile()
{
	m_file = NULL;
}

// FUNCTION: LEGO1 0x10099250
LegoFile::~LegoFile()
{
	if (m_file) {
		fclose(m_file);
	}
}

// FUNCTION: LEGO1 0x100992c0
LegoResult LegoFile::Read(void* p_buffer, LegoU32 p_size)
{
	if (!m_file) {
		return FAILURE;
	}
	if (fread(p_buffer, 1, p_size, m_file) != p_size) {
		return FAILURE;
	}
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10099300
LegoResult LegoFile::Write(const void* p_buffer, LegoU32 p_size)
{
	if (!m_file) {
		return FAILURE;
	}
	if (fwrite(p_buffer, 1, p_size, m_file) != p_size) {
		return FAILURE;
	}
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10099340
LegoResult LegoFile::GetPosition(LegoU32& p_position)
{
	if (!m_file) {
		return FAILURE;
	}
	LegoU32 position = ftell(m_file);
	if (position == -1) {
		return FAILURE;
	}
	p_position = position;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10099370
LegoResult LegoFile::SetPosition(LegoU32 p_position)
{
	if (!m_file) {
		return FAILURE;
	}
	if (fseek(m_file, p_position, SEEK_SET) != 0) {
		return FAILURE;
	}
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100993a0
LegoResult LegoFile::Open(const char* p_name, LegoU32 p_mode)
{
	if (m_file) {
		fclose(m_file);
	}
	char mode[4];
	mode[0] = '\0';
	if (p_mode & c_read) {
		m_mode = c_read;
		strcat(mode, "r");
	}
	if (p_mode & c_write) {
		if (m_mode != c_read) {
			m_mode = c_write;
		}
		strcat(mode, "w");
	}
	if ((p_mode & c_text) != 0) {
		strcat(mode, "t");
	}
	else {
		strcat(mode, "b");
	}

	if (!(m_file = fopen(p_name, mode))) {
		return FAILURE;
	}
	return SUCCESS;
}
