#ifndef MXDSOBJECT_H
#define MXDSOBJECT_H

#include "decomp.h"
#include "mxatom.h"
#include "mxcore.h"
#include "mxutilitylist.h"

class MxDSFile;
class MxDSObject;
class MxPresenter;

// SIZE 0x0c
class MxDSObjectList : public MxUtilityList<MxDSObject*> {
public:
	// FUNCTION: BETA10 0x10150e30
	MxDSObject* FindAndErase(MxDSObject* p_action) { return FindInternal(p_action, TRUE); }

	// FUNCTION: BETA10 0x10150fc0
	MxDSObject* Find(MxDSObject* p_action) { return FindInternal(p_action, FALSE); }

private:
	MxDSObject* FindInternal(MxDSObject* p_action, MxBool p_delete);
};

// VTABLE: LEGO1 0x100dc868
// VTABLE: BETA10 0x101c23f0
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
	MxDSObject(MxDSObject& p_dsObject);
	MxDSObject& operator=(MxDSObject& p_dsObject);

	void SetObjectName(const char* p_objectName);
	void SetSourceName(const char* p_sourceName);

	// FUNCTION: LEGO1 0x100bf730
	// FUNCTION: BETA10 0x1012bdd0
	const char* ClassName() const override { return "MxDSObject"; } // vtable+0c

	// FUNCTION: LEGO1 0x100bf740
	// FUNCTION: BETA10 0x1012bd70
	MxBool IsA(const char* p_name) const override
	{
		return !strcmp(p_name, MxDSObject::ClassName()) || MxCore::IsA(p_name);
	} // vtable+10;

	virtual undefined4 VTable0x14();                            // vtable+14;
	virtual MxU32 GetSizeOnDisk();                              // vtable+18;
	virtual void Deserialize(MxU8*& p_source, MxS16 p_unk0x24); // vtable+1c;

	// FUNCTION: ISLE 0x401c40
	// FUNCTION: LEGO1 0x10005530
	// FUNCTION: BETA10 0x100152e0
	virtual void SetAtomId(MxAtomId p_atomId) { m_atomId = p_atomId; } // vtable+20;

	// FUNCTION: BETA10 0x1012ef90
	Type GetType() const { return (Type) m_type; }

	// FUNCTION: BETA10 0x1012efb0
	const char* GetSourceName() const { return m_sourceName; }

	// FUNCTION: BETA10 0x10028460
	const char* GetObjectName() const { return m_objectName; }

	// FUNCTION: BETA10 0x10017910
	MxU32 GetObjectId() { return m_objectId; }

	// FUNCTION: BETA10 0x10017940
	const MxAtomId& GetAtomId() { return m_atomId; }

	MxS16 GetUnknown24() { return m_unk0x24; }
	MxPresenter* GetUnknown28() { return m_unk0x28; }

	void SetType(Type p_type) { m_type = p_type; }

	// FUNCTION: BETA10 0x100152b0
	void SetObjectId(MxU32 p_objectId) { m_objectId = p_objectId; }

	// FUNCTION: BETA10 0x10039570
	void SetUnknown24(MxS16 p_unk0x24) { m_unk0x24 = p_unk0x24; }

	void SetUnknown28(MxPresenter* p_unk0x28) { m_unk0x28 = p_unk0x28; }

	void ClearAtom() { m_atomId.Clear(); }

	// SYNTHETIC: LEGO1 0x100bf7c0
	// SYNTHETIC: BETA10 0x10148770
	// MxDSObject::`scalar deleting destructor'

protected:
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
MxDSObject* CreateStreamObject(MxDSFile*, MxS16);

// TEMPLATE: BETA10 0x10150950
// MxUtilityList<MxDSObject *>::PopFront

#endif // MXDSOBJECT_H
