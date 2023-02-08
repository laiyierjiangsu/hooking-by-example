#include "getnum-dll.h"
#include <iostream>
int GetNum()
{
	return 1;
}


#pragma optimize( "", off )
int expresstion0(int a, int b, int c)
{
	return a + b + c;
}
int expression1(int a, int b, int c)
{
	return a * b * c - a + b;
}
int expression2(int a, int b, int c)
{
	auto r0 = expresstion0(a, b, c);
	printf("r0 = %d\n", r0);
	auto r1 = expression1(a, b, c);
	printf("r1 = %d\n", r1);
	return r0 + r1;
}
#pragma optimize( "", on )
