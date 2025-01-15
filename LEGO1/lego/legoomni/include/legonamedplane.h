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

	// FUNCTION: LEGO1 0x10033a70
	// LegoNamedPlane::~LegoNamedPlane

	const char* GetName() const { return m_name.GetData(); }
	const Mx3DPointFloat& GetPosition() { return m_position; }
	const Mx3DPointFloat& GetDirection() { return m_direction; }
	const Mx3DPointFloat& GetUp() { return m_up; }

	void SetName(const char* p_name) { m_name = p_name; }
	void SetPosition(const Mx3DPointFloat& p_position) { m_position = p_position; }
	void SetDirection(const Mx3DPointFloat& p_direction) { m_direction = p_direction; }
	void SetUp(const Mx3DPointFloat& p_up) { m_up = p_up; }

	// TODO: Unclear whether this was defined
	MxBool IsPresent() { return strcmp(m_name.GetData(), "") != 0; }
	void Reset() { m_name = ""; }

	// FUNCTION: LEGO1 0x100344d0
	MxResult Serialize(LegoFile* p_file)
	{
		if (p_file->IsWriteMode()) {
			p_file->Write(MxString(m_name));
			p_file->Write(m_position);
			p_file->Write(m_direction);
			p_file->Write(m_up);
		}
		else if (p_file->IsReadMode()) {
			p_file->Read(m_name);
			p_file->Read(m_position);
			p_file->Read(m_direction);
			p_file->Read(m_up);
		}

		return SUCCESS;
	}

	// private:
	MxString m_name;            // 0x00
	Mx3DPointFloat m_position;  // 0x10
	Mx3DPointFloat m_direction; // 0x24
	Mx3DPointFloat m_up;        // 0x38
};

#endif // LEGONAMEDPLANE_H
