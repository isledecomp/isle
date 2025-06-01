#ifndef LEGOPHONEME_H
#define LEGOPHONEME_H

#include "decomp.h"
#include "mxstring.h"

class LegoTextureInfo;

// VTABLE: LEGO1 0x100d7c88
// SIZE 0x20
class LegoPhoneme {
public:
	LegoPhoneme(const char* p_name, MxU32 p_count)
	{
		m_name = p_name;
		m_name.ToUpperCase();
		Init();
		m_count = p_count;
	}
	~LegoPhoneme();

	virtual MxU32 GetCount();                                                // vtable+0x00
	virtual void SetCount(MxU32 p_count);                                    // vtable+0x04
	virtual LegoTextureInfo* GetTextureInfo();                               // vtable+0x08
	virtual void SetTextureInfo(LegoTextureInfo* p_textureInfo);             // vtable+0x0c
	virtual LegoTextureInfo* GetCachedTextureInfo();                         // vtable+0x10
	virtual void SetCachedTextureInfo(LegoTextureInfo* p_cachedTextureInfo); // vtable+0x14
	virtual void VTable0x18();                                               // vtable+0x18
	virtual void Init();                                                     // vtable+0x1c
	virtual void VTable0x20(undefined4);                                     // vtable+0x20

	MxString& GetName() { return m_name; }

private:
	MxString m_name;                      // 0x04
	MxU32 m_count;                        // 0x14
	LegoTextureInfo* m_textureInfo;       // 0x18
	LegoTextureInfo* m_cachedTextureInfo; // 0x1c
};

#endif // LEGOPHONEME_H
