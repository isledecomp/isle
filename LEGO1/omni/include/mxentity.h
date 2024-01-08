#ifndef MXENTITY_H
#define MXENTITY_H

#include "decomp.h"
#include "mxatomid.h"
#include "mxcore.h"
#include "mxdsobject.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d5390
// SIZE 0x10
class MxEntity : public MxCore {
public:
	MxEntity();
	virtual ~MxEntity() override;

	// FUNCTION: LEGO1 0x1000c180
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0070
		return "MxEntity";
	}

	// FUNCTION: LEGO1 0x1000c190
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxEntity::ClassName()) || MxCore::IsA(p_name);
	}

	virtual MxResult Create(MxS32 p_id, const MxAtomId& p_atom); // vtable+0x14
	inline MxResult Create(MxDSObject& p_dsObject)
	{
		m_mxEntityId = p_dsObject.GetObjectId();
		m_atom = p_dsObject.GetAtomId();
		return SUCCESS;
	}

protected:
	MxS32 m_mxEntityId; // 0x8
	MxAtomId m_atom;    // 0xc
};

#endif // MXENTITY_H
