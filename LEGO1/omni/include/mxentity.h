#ifndef MXENTITY_H
#define MXENTITY_H

#include "decomp.h"
#include "mxatomid.h"
#include "mxcore.h"
#include "mxdsaction.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d5390
// SIZE 0x10
class MxEntity : public MxCore {
public:
	// FUNCTION: LEGO1 0x1001d190
	MxEntity() { this->m_mxEntityId = -1; }

	// FUNCTION: LEGO1 0x1000c110
	~MxEntity() override {}

	// FUNCTION: LEGO1 0x1000c180
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0070
		return "MxEntity";
	}

	// FUNCTION: LEGO1 0x1000c190
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxEntity::ClassName()) || MxCore::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x10001070
	virtual MxResult Create(MxS32 p_id, const MxAtomId& p_atom)
	{
		this->m_mxEntityId = p_id;
		this->m_atom = p_atom;
		return SUCCESS;
	} // vtable+0x14

	inline MxResult Create(MxDSAction& p_dsAction)
	{
		m_mxEntityId = p_dsAction.GetObjectId();
		m_atom = p_dsAction.GetAtomId();
		return SUCCESS;
	}

	inline MxS32 GetEntityId() { return m_mxEntityId; }
	inline MxAtomId& GetAtom() { return m_atom; }

	// SYNTHETIC: LEGO1 0x1000c210
	// MxEntity::`scalar deleting destructor'

protected:
	MxS32 m_mxEntityId; // 0x08
	MxAtomId m_atom;    // 0x0c
};

#endif // MXENTITY_H
