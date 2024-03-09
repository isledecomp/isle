#ifndef LEGONAMEDPART_H
#define LEGONAMEDPART_H

#include "legolodlist.h"
#include "mxstring.h"

// SIZE 0x14
class LegoNamedPart {
public:
	LegoNamedPart(const char* p_name, LegoLODList* p_list)
	{
		m_name = p_name;
		m_list = p_list;
	}
	~LegoNamedPart() { delete m_list; }

	const MxString* GetName() const { return &m_name; }
	LegoLODList* GetList() { return m_list; }

private:
	MxString m_name;     // 0x00
	LegoLODList* m_list; // 0x04
};

#endif // LEGONAMEDPART_H
