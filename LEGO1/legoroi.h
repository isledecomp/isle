#ifndef LEGOROI_H
#define LEGOROI_H

class LegoROI {
public:
	__declspec(dllexport) void SetDisplayBB(int p_displayBB);
	__declspec(dllexport) static void configureLegoROI(int p_roi);
};

#endif // LEGOROI_H
