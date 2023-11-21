#ifndef MXDSOBJECT_H
#define MXDSOBJECT_H

#include "decomp.h"
#include "mxatomid.h"
#include "mxcore.h"
#include "mxdstypes.h"

// TODO: Find proper compilation unit to put this
// OFFSET: LEGO1 0x10005530 TEMPLATE
// MxDSObject::SetAtomId

// VTABLE 0x100dc868
// SIZE 0x2c
class MxDSObject : public MxCore {
public:
	MxDSObject();
	virtual ~MxDSObject() override;

	void CopyFrom(MxDSObject& p_dsObject);
	MxDSObject& operator=(MxDSObject& p_dsObject);

	__declspec(dllexport) void SetObjectName(const char* p_objectName);
	void SetSourceName(const char* p_sourceName);

	// OFFSET: LEGO1 0x100bf730
	inline virtual const char* ClassName() const override { return "MxDSObject"; }; // vtable+0c

	// OFFSET: LEGO1 0x100bf740
	inline virtual MxBool IsA(const char* name) const override
	{
		return !strcmp(name, MxDSObject::ClassName()) || MxCore::IsA(name);
	}; // vtable+10;

	virtual undefined4 unk14();                                                     // vtable+14;
	virtual MxU32 GetSizeOnDisk();                                                  // vtable+18;
	virtual void Deserialize(char** p_source, MxS16 p_unk24);                       // vtable+1c;
	inline virtual void SetAtomId(MxAtomId p_atomId) { this->m_atomId = p_atomId; } // vtable+20;

	inline const MxAtomId& GetAtomId() { return this->m_atomId; }
	inline MxU32 GetObjectId() { return this->m_objectId; }
	inline MxS16 GetUnknown24() { return this->m_unk24; }

	inline void SetObjectId(MxU32 p_objectId) { this->m_objectId = p_objectId; }
	inline void SetUnknown24(MxS16 p_unk24) { this->m_unk24 = p_unk24; }

	inline const char* GetSourceName() const { return this->m_sourceName; }

	inline void SetType(MxDSType p_type) { this->m_type = p_type; }
	inline MxDSType GetType() const { return (MxDSType) this->m_type; }

private:
	MxU32 m_sizeOnDisk; // 0x8
	MxU16 m_type;       // 0xc
	char* m_sourceName; // 0x10
	undefined4 m_unk14; // 0x14
	char* m_objectName; // 0x18
	MxU32 m_objectId;   // 0x1c
	MxAtomId m_atomId;  // 0x20
	MxS16 m_unk24;      // 0x24
	undefined4 m_unk28; // 0x28
};

MxDSObject* DeserializeDSObjectDispatch(char**, MxS16);

#endif // MXDSOBJECT_H
