#ifndef LEGOPHONEME_H
#define LEGOPHONEME_H

#include "decomp.h"
#include "mxstring.h"

class LegoTextureInfo;

// VTABLE: LEGO1 0x100d7c88
// SIZE 0x20
class LegoPhoneme {
public:
	LegoPhoneme(const char* p_name, undefined4 p_unk0x14)
	{
		m_name = p_name;
		m_name.ToUpperCase();
		Init();
		m_unk0x14 = p_unk0x14;
	}
	~LegoPhoneme();

	virtual undefined4 VTable0x00();                     // vtable+0x00
	virtual void VTable0x04(undefined4 p_unk0x14);       // vtable+0x04
	virtual LegoTextureInfo* VTable0x08();               // vtable+0x08
	virtual void VTable0x0c(LegoTextureInfo* p_unk0x18); // vtable+0x0c
	virtual LegoTextureInfo* VTable0x10();               // vtable+0x10
	virtual void VTable0x14(LegoTextureInfo* p_unk0x1c); // vtable+0x14
	virtual void VTable0x18();                           // vtable+0x18
	virtual void Init();                                 // vtable+0x1c
	virtual void VTable0x20(undefined4);                 // vtable+0x20

	MxString& GetName() { return m_name; }

private:
	MxString m_name;            // 0x04
	undefined4 m_unk0x14;       // 0x14
	LegoTextureInfo* m_unk0x18; // 0x18
	LegoTextureInfo* m_unk0x1c; // 0x1c
};

#endif // LEGOPHONEME_H
