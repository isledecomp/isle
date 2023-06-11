#ifndef MXPALETTE_H
#define MXPALETTE_H

class MxPalette
{
public:
	void __declspec(dllexport) Detach(void);
	unsigned char __declspec(dllexport) operator==(MxPalette &palette);
};

#endif // MXPALETTE_H
