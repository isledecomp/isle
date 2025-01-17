#ifndef LEGONAMEDPLANE_H
#define LEGONAMEDPLANE_H

#include "misc/legostorage.h"
#include "mxgeometry/mxgeometry3d.h"
#include "mxstring.h"

// SIZE 0x4c
struct LegoNamedPlane {
	// FUNCTION: LEGO1 0x10033800
	LegoNamedPlane() {}

	// FUNCTION: LEGO1 0x10033a70
	// LegoNamedPlane::~LegoNamedPlane

	// Unclear whether getters/setters were used.
	// Act1State::Serialize seems to access `m_name` directly (only matches like that)
	// Act1State::PlaceActors though seems to require extensive use of getters to improve

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
	MxResult Serialize(LegoStorage* p_storage)
	{
		if (p_storage->IsWriteMode()) {
			p_storage->WriteMxString(m_name);
			p_storage->WriteVector(m_position);
			p_storage->WriteVector(m_direction);
			p_storage->WriteVector(m_up);
		}
		else if (p_storage->IsReadMode()) {
			p_storage->ReadMxString(m_name);
			p_storage->ReadVector(m_position);
			p_storage->ReadVector(m_direction);
			p_storage->ReadVector(m_up);
		}

		return SUCCESS;
	}

	MxString m_name;            // 0x00
	Mx3DPointFloat m_position;  // 0x10
	Mx3DPointFloat m_direction; // 0x24
	Mx3DPointFloat m_up;        // 0x38
};

#endif // LEGONAMEDPLANE_H
