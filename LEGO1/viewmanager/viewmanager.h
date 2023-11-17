#ifndef VIEWMANAGER_H
#define VIEWMANAGER_H

class ViewROI;

class ViewManager {
public:
	__declspec(dllexport) void RemoveAll(ViewROI*);
};

#endif // VIEWMANAGER_H
