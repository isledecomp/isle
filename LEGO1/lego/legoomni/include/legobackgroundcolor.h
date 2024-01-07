#ifndef LEGOBACKGROUNDCOLOR_H
#define LEGOBACKGROUNDCOLOR_H

#include "mxvariable.h"

// VTABLE: LEGO1 0x100d74a8
// SIZE 0x30
class LegoBackgroundColor : public MxVariable {
public:
	__declspec(dllexport) LegoBackgroundColor(const char* p_key, const char* p_value);
	virtual void SetValue(const char* p_colorString) override;

private:
	float m_h;
	float m_s;
	float m_v;
};

#endif // LEGOBACKGROUNDCOLOR_H
