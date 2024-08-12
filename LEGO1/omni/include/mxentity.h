#ifndef MXENTITY_H
#define MXENTITY_H

#include "decomp.h"
#include "mxatom.h"
#include "mxcore.h"
#include "mxdsaction.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d5390
// SIZE 0x10
class MxEntity : public MxCore {
public:
	// FUNCTION: LEGO1 0x1001d190
	MxEntity() { m_entityId = -1; }

	// FUNCTION: LEGO1 0x1000c110
	~MxEntity() override {}

	// FUNCTION: LEGO1 0x1000c180
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0070
		return "MxEntity";
	}

	// FUNCTION: LEGO1 0x1000c190
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxEntity::ClassName()) || MxCore::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x10001070
	virtual MxResult Create(MxS32 p_entityId, const MxAtomId& p_atomId)
	{
		m_entityId = p_entityId;
		m_atomId = p_atomId;
		return SUCCESS;
	} // vtable+0x14

	MxResult Create(MxDSAction& p_dsAction)
	{
		m_entityId = p_dsAction.GetObjectId();
		m_atomId = p_dsAction.GetAtomId();
		return SUCCESS;
	}

	MxS32 GetEntityId() { return m_entityId; }
	MxAtomId& GetAtomId() { return m_atomId; }

	void SetEntityId(MxS32 p_entityId) { m_entityId = p_entityId; }
	void SetAtomId(const MxAtomId& p_atomId) { m_atomId = p_atomId; }

	// SYNTHETIC: LEGO1 0x1000c210
	// MxEntity::`scalar deleting destructor'

protected:
	MxS32 m_entityId;  // 0x08
	MxAtomId m_atomId; // 0x0c
};

#endif // MXENTITY_H
