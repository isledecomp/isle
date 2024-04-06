#ifndef MXDSOBJECT_H
#define MXDSOBJECT_H

#include "decomp.h"
#include "mxatom.h"
#include "mxcore.h"

class MxPresenter;

// VTABLE: LEGO1 0x100dc868
// SIZE 0x2c
class MxDSObject : public MxCore {
public:
	enum Type {
		e_object = 0,
		e_action,
		e_mediaAction,
		e_anim,
		e_sound,
		e_multiAction,
		e_serialAction,
		e_parallelAction,
		e_event,
		e_selectAction,
		e_still,
		e_objectAction,
	};

	MxDSObject();
	~MxDSObject() override;

	void CopyFrom(MxDSObject& p_dsObject);
	MxDSObject& operator=(MxDSObject& p_dsObject);

	void SetObjectName(const char* p_objectName);
	void SetSourceName(const char* p_sourceName);

	// FUNCTION: LEGO1 0x100bf730
	inline const char* ClassName() const override { return "MxDSObject"; } // vtable+0c

	// FUNCTION: LEGO1 0x100bf740
	inline MxBool IsA(const char* p_name) const override
	{
		return !strcmp(p_name, MxDSObject::ClassName()) || MxCore::IsA(p_name);
	} // vtable+10;

	virtual undefined4 VTable0x14();                            // vtable+14;
	virtual MxU32 GetSizeOnDisk();                              // vtable+18;
	virtual void Deserialize(MxU8*& p_source, MxS16 p_unk0x24); // vtable+1c;

	// FUNCTION: ISLE 0x401c40
	// FUNCTION: LEGO1 0x10005530
	inline virtual void SetAtomId(MxAtomId p_atomId) { this->m_atomId = p_atomId; } // vtable+20;

	inline Type GetType() const { return (Type) this->m_type; }
	inline const char* GetSourceName() const { return this->m_sourceName; }
	inline const char* GetObjectName() const { return this->m_objectName; }
	inline MxU32 GetObjectId() { return this->m_objectId; }
	inline const MxAtomId& GetAtomId() { return this->m_atomId; }
	inline MxS16 GetUnknown24() { return this->m_unk0x24; }
	inline MxPresenter* GetUnknown28() { return this->m_unk0x28; }

	inline void SetType(Type p_type) { this->m_type = p_type; }
	inline void SetObjectId(MxU32 p_objectId) { this->m_objectId = p_objectId; }
	inline void SetUnknown24(MxS16 p_unk0x24) { this->m_unk0x24 = p_unk0x24; }
	inline void SetUnknown28(MxPresenter* p_unk0x28) { this->m_unk0x28 = p_unk0x28; }

	inline void ClearAtom() { m_atomId.Clear(); }

	// SYNTHETIC: LEGO1 0x100bf7c0
	// MxDSObject::`scalar deleting destructor'

private:
	MxU32 m_sizeOnDisk;     // 0x08
	MxU16 m_type;           // 0x0c
	char* m_sourceName;     // 0x10
	undefined4 m_unk0x14;   // 0x14
	char* m_objectName;     // 0x18
	MxU32 m_objectId;       // 0x1c
	MxAtomId m_atomId;      // 0x20
	MxS16 m_unk0x24;        // 0x24
	MxPresenter* m_unk0x28; // 0x28
};

MxDSObject* DeserializeDSObjectDispatch(MxU8*&, MxS16);

#endif // MXDSOBJECT_H
