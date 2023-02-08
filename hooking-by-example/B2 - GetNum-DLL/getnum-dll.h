#pragma once
#define DllExport   __declspec( dllexport )

extern "C"
{
	DllExport __declspec(noinline) int GetNum();
	DllExport __declspec(noinline) int expression2(int a, int b, int c);
}
