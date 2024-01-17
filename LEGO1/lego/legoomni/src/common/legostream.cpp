
#include "legostream.h"

#include "mxvariabletable.h"

#include <cstdio>
#include <string>

// This is a pointer to the end of the global variable name table, which has
// the text "END_OF_VARIABLES" in it.
// TODO: make g_endOfVariables reference the actual end of the variable array.
// GLOBAL: LEGO1 0x100f3e50
// STRING: LEGO1 0x100f3e00
const char* g_endOfVariables = "END_OF_VARIABLES";

// Very likely but not certain sizes.
// The classes are only used on the stack in functions we have not 100% matched
// yet, we can confirm the size once we have.
DECOMP_SIZE_ASSERT(LegoStream, 0x8);
DECOMP_SIZE_ASSERT(LegoFileStream, 0xC);
DECOMP_SIZE_ASSERT(LegoMemoryStream, 0x10);

// FUNCTION: LEGO1 0x10039f70
MxResult LegoStream::WriteVariable(LegoStream* p_stream, MxVariableTable* p_from, const char* p_variableName)
{
	MxResult result = FAILURE;
	const char* variableValue = p_from->GetVariable(p_variableName);

	if (variableValue) {
		MxU8 length = strlen(p_variableName);
		if (p_stream->Write((char*) &length, 1) == SUCCESS) {
			if (p_stream->Write(p_variableName, length) == SUCCESS) {
				length = strlen(variableValue);
				if (p_stream->Write((char*) &length, 1) == SUCCESS)
					result = p_stream->Write((char*) variableValue, length);
			}
		}
	}
	return result;
}

// 95% match, just some instruction ordering differences on the call to
// MxVariableTable::SetVariable at the end.
// FUNCTION: LEGO1 0x1003a080
MxS32 LegoStream::ReadVariable(LegoStream* p_stream, MxVariableTable* p_to)
{
	MxS32 result = 1;
	MxU8 length;

	if (p_stream->Read((char*) &length, 1) == SUCCESS) {
		char nameBuffer[256];
		if (p_stream->Read(nameBuffer, length) == SUCCESS) {
			nameBuffer[length] = '\0';
			if (strcmp(nameBuffer, g_endOfVariables) == 0)
				// 2 -> "This was the last entry, done reading."
				result = 2;
			else {
				if (p_stream->Read((char*) &length, 1) == SUCCESS) {
					char valueBuffer[256];
					if (p_stream->Read(valueBuffer, length) == SUCCESS) {
						result = 0;
						valueBuffer[length] = '\0';
						p_to->SetVariable(nameBuffer, valueBuffer);
					}
				}
			}
		}
	}
	return result;
}

// FUNCTION: LEGO1 0x10045ae0
MxBool LegoStream::IsWriteMode()
{
	return m_mode == LEGOSTREAM_MODE_WRITE;
}

// FUNCTION: LEGO1 0x10045af0
MxBool LegoStream::IsReadMode()
{
	return m_mode == LEGOSTREAM_MODE_READ;
}

// FUNCTION: LEGO1 0x10099080
LegoMemoryStream::LegoMemoryStream(char* p_buffer) : LegoStream()
{
	m_buffer = p_buffer;
	m_offset = 0;
}

// FUNCTION: LEGO1 0x10099160
MxResult LegoMemoryStream::Read(void* p_buffer, MxU32 p_size)
{
	memcpy(p_buffer, m_buffer + m_offset, p_size);
	m_offset += p_size;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10099190
MxResult LegoMemoryStream::Write(const void* p_buffer, MxU32 p_size)
{
	memcpy(m_buffer + m_offset, p_buffer, p_size);
	m_offset += p_size;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100991c0
LegoFileStream::LegoFileStream() : LegoStream()
{
	m_hFile = NULL;
}

// FUNCTION: LEGO1 0x10099250
LegoFileStream::~LegoFileStream()
{
	if (m_hFile != NULL)
		fclose(m_hFile);
}

// FUNCTION: LEGO1 0x100992c0
MxResult LegoFileStream::Read(void* p_buffer, MxU32 p_size)
{
	if (m_hFile == NULL)
		return FAILURE;

	return (fread(p_buffer, 1, p_size, m_hFile) == p_size) ? SUCCESS : FAILURE;
}

// FUNCTION: LEGO1 0x10099300
MxResult LegoFileStream::Write(const void* p_buffer, MxU32 p_size)
{
	if (m_hFile == NULL)
		return FAILURE;

	return (fwrite(p_buffer, 1, p_size, m_hFile) == p_size) ? SUCCESS : FAILURE;
}

// FUNCTION: LEGO1 0x10099340
MxResult LegoFileStream::Tell(MxU32* p_offset)
{
	if (m_hFile == NULL)
		return FAILURE;

	int got = ftell(m_hFile);
	if (got == -1)
		return FAILURE;

	*p_offset = got;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x10099370
MxResult LegoFileStream::Seek(MxU32 p_offset)
{
	if (m_hFile == NULL)
		return FAILURE;

	return (fseek(m_hFile, p_offset, 0) == 0) ? SUCCESS : FAILURE;
}

// FUNCTION: LEGO1 0x100993a0
MxResult LegoFileStream::Open(const char* p_filename, OpenFlags p_mode)
{
	char modeString[4];

	if (m_hFile != NULL)
		fclose(m_hFile);

	modeString[0] = '\0';
	if (p_mode & c_readBit) {
		m_mode = LEGOSTREAM_MODE_READ;
		strcat(modeString, "r");
	}

	if (p_mode & c_writeBit) {
		if (m_mode != LEGOSTREAM_MODE_READ)
			m_mode = LEGOSTREAM_MODE_WRITE;
		strcat(modeString, "w");
	}

	if ((p_mode & c_binaryBit) != 0)
		strcat(modeString, "b");
	else
		strcat(modeString, "t");

	return (m_hFile = fopen(p_filename, modeString)) ? SUCCESS : FAILURE;
}

// FUNCTION: LEGO1 0x100994a0
MxResult LegoMemoryStream::Tell(MxU32* p_offset)
{
	*p_offset = m_offset;
	return SUCCESS;
}

// FUNCTION: LEGO1 0x100994b0
MxResult LegoMemoryStream::Seek(MxU32 p_offset)
{
	m_offset = p_offset;
	return SUCCESS;
}
