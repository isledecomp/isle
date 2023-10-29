#ifndef LEGOBACKGROUNDCOLOR_H
#define LEGOBACKGROUNDCOLOR_H

#include "mxvariable.h"

// VTABLE 0x100d74a8
// SIZE 0x30
class LegoBackgroundColor : public MxVariable {
public:
	__declspec(dllexport) LegoBackgroundColor(const char* p_key, const char* p_value);
	virtual void SetValue(const char* p_colorString) override;

private:
	float h;
	float s;
	float v;
};

#endif // LEGOBACKGROUNDCOLOR_H
