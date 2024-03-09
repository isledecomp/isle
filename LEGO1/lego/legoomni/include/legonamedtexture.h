#ifndef LEGONAMEDTEXTURE_H
#define LEGONAMEDTEXTURE_H

#include "misc/legotexture.h"
#include "mxstring.h"

// SIZE 0x14
class LegoNamedTexture {
public:
	LegoNamedTexture(const char* p_name, LegoTexture* p_texture)
	{
		m_name = p_name;
		m_texture = p_texture;
	}
	~LegoNamedTexture() { delete m_texture; }

	// FUNCTION: LEGO1 0x1003f920
	const MxString* GetName() const { return &m_name; }

	LegoTexture* GetTexture() { return m_texture; }

private:
	MxString m_name;        // 0x00
	LegoTexture* m_texture; // 0x04
};

#endif // LEGONAMEDTEXTURE_H
