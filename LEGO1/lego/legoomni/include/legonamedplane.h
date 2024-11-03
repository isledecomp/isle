#ifndef LEGONAMEDPLANE_H
#define LEGONAMEDPLANE_H

#include "misc/legostorage.h"
#include "mxgeometry/mxgeometry3d.h"
#include "mxstring.h"

// SIZE 0x4c
class LegoNamedPlane {
public:
	// FUNCTION: LEGO1 0x10033800
	LegoNamedPlane() {}

	void SetName(const char* p_name) { m_name = p_name; }
	const MxString* GetName() const { return &m_name; }

	// FUNCTION: LEGO1 0x100344d0
	MxResult Serialize(LegoFile* p_file)
	{
		if (p_file->IsWriteMode()) {
			p_file->WriteString(m_name);
			p_file->WriteVector3(m_position);
			p_file->WriteVector3(m_direction);
			p_file->WriteVector3(m_up);
		}
		else if (p_file->IsReadMode()) {
			p_file->ReadString(m_name);
			p_file->ReadVector3(m_position);
			p_file->ReadVector3(m_direction);
			p_file->ReadVector3(m_up);
		}

		return SUCCESS;
	}

private:
	MxString m_name;            // 0x00
	Mx3DPointFloat m_position;  // 0x10
	Mx3DPointFloat m_direction; // 0x24
	Mx3DPointFloat m_up;        // 0x38
};

#endif // LEGONAMEDPLANE_H
