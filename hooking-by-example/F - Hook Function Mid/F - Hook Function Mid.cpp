// F - Hook Function Mid.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "../hooking_common.h"
#include "../trampoline_common.h"
#include <stack>
#include <Windows.h>

extern "C" void __fastcall asm_func(const char* lpText);
extern "C" void __fastcall asm_payload(const char* lpText);

extern "C" UINT GetMsgBoxType()
{
	return MB_YESNOCANCEL | MB_ICONINFORMATION;
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


void WriteTrampoline(void* dst, void* payloadFuncAddr, void* func2hook, uint8_t* stolenBytes, uint32_t numStolenBytes)
{


}
//thread local assembly is gnarly, so let's let the compiler handle it, we'll just call these funcs
thread_local std::stack<uint64_t> hookJumpAddresses;

void PushAddress(uint64_t addr) //push the address of the jump target
{
	hookJumpAddresses.push(addr);
}

void PopAddress(uint64_t trampolinePtr)
{
	uint64_t addr = hookJumpAddresses.top();
	hookJumpAddresses.pop();
	memcpy((void*)trampolinePtr, &addr, sizeof(uint64_t));
}

thread_local int (*expression_2_func_ptr)(int, int, int);
__declspec(noinline)  __declspec(safebuffers) extern "C"  void payload(UINT64 rcx, UINT64 rdx, UINT64 r8, UINT64 r9)
{
	//CONTEXT context;
	//RtlCaptureContext(&context);
	//因为前面获取线程context的调用，导致堆栈内寄存器的数值已经发生变化，需要进行恢复
//	context.Rcx = rcx;

	printf("This is a payload fuction\n");
	//asm_func("Hello world!");

	PopAddress(uint64_t(&expression_2_func_ptr));

	//How to get register values
	(*expression_2_func_ptr)(rcx, rdx, r8);
}


void InstallHook(void* func2hook, void* payloadFunc)
{
	SetOtherThreadsSuspended(true);

	DWORD oldProtect;
	VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	void* hookMemory = AllocatePageNearAddress(func2hook);

	//pre_payload_size is the size of the "pre-payload" instructions that are written below
	//the trampoline will be located after these instructions in memory
	//pre_payload_size = int(memoryIter - hookMemory)
	UINT pre_payload_size = 140;
	uint32_t trampolineSize = BuildTrampoline(func2hook, (void*)((char*)hookMemory + pre_payload_size));

	uint8_t* memoryIter = (uint8_t*)hookMemory;
	uint64_t trampolineAddress = (uint64_t)(memoryIter)+pre_payload_size;

	memoryIter += WriteSaveContext(memoryIter);
	memoryIter += WriteMovToRCX(memoryIter, trampolineAddress);
	memoryIter += WriteSubRSP32(memoryIter); //allocate home space for function call
	memoryIter += WriteAbsoluteCall64(memoryIter, &PushAddress);
	memoryIter += WriteAddRSP32(memoryIter);
	memoryIter += WriteRestoreContext(memoryIter);
	memoryIter += WriteAbsoluteJump64(memoryIter, payloadFunc);

	//printf("size = %d", int(memoryIter - hookMemory));

	//create the relay function
	void* relayFuncMemory = memoryIter + trampolineSize;
	WriteAbsoluteJump64(relayFuncMemory, hookMemory); //write relay func instructions

	//install the hook
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
	const int32_t relAddr = int32_t((int64_t)relayFuncMemory - ((int64_t)func2hook + sizeof(jmpInstruction)));
	memcpy(jmpInstruction + 1, &relAddr, 4);
	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));

	SetOtherThreadsSuspended(false);
	printf("hook installed!\n");
}

//almost certainly specific to MSVC, lets you get a void*
//from a pointer to member function
template<typename FuncSig>
inline void* GetFuncPointer(FuncSig func)
{
	char** ptrptr = (char**)(&func);
	return (void*)(*ptrptr);
}

//只调转到payLoad函数，并不执行原来的函数
void HookJumpToPayload()
{
	void* target_fun = (void*)((UINT64)(&expression2)+0x26);
	void* payload_fun = &payload;

	DWORD oldProtect;
	bool err = VirtualProtect(target_fun, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	uint8_t stolenBytes[5];
	memcpy(stolenBytes, target_fun, sizeof(stolenBytes));

	void* trampolineMemory = AllocatePageNearAddress(target_fun);
	//	auto  = (void*)trampolineMemory;
		//the trampoline consists of the stolen bytes from the target function, following by a jump back
		//to the target function + 5 bytes, in order to continue the execution of that function. This continues like
		//a normal function call
	void* trampolineJumpTarget = ((uint8_t*)target_fun + 5);

	uint8_t* dstIter = (uint8_t*)trampolineMemory;
	memcpy(dstIter, stolenBytes, sizeof(stolenBytes));
	dstIter += sizeof(stolenBytes);
	dstIter += WriteAbsoluteJump64(dstIter, trampolineJumpTarget);

	WriteRelativeJump(target_fun, payload_fun);

}

//从函数中间进行hook
typedef int (*dll_expression2)(int a, int b, int c);
void HookFromMidWithPayload()
{
	HINSTANCE hGetProcIDDLL = LoadLibrary("B2 - GetNum-DLL.dll");
	if (!hGetProcIDDLL) {
		std::cout << "could not load the dynamic library" << std::endl;
		return ;
	}
	// resolve function address here
	auto  dll_expression = (dll_expression2)GetProcAddress(hGetProcIDDLL, "expression2");
	if (!dll_expression) {
		std::cout << "could not locate the function" << std::endl;
		return ;
	}

	//void* target_fun = (void*)((UINT64)(&expression2) + 0x26);
	auto  v_target_fun = (UINT64)dll_expression;
	auto  v_offset_fun = (UINT64)hGetProcIDDLL + 4304;
	printf("dll_expression offset :0x%Ix, original : 0x%Ix\n", v_offset_fun, v_target_fun);

	//expression2: 尝试在两次printf中间的位置进行hook
	v_offset_fun = (UINT64)hGetProcIDDLL + 4359;
	void* target_fun = (void*)v_offset_fun;
	void* payload_fun = &asm_payload;
	InstallHook(target_fun, payload_fun);

	int a = 10, b = 20, c = 30;
	std::cout << "dll_expression() returned " << dll_expression(a, b, c) << std::endl;
}

//从函数开头hook
void HookFromBeginWithPayLoad()
{
	//Jump and execute original
	void* target_fun = (void*)((UINT64)(&expression2) + 0x26);
	void* payload_fun = &asm_payload;
	InstallHook(target_fun, payload_fun);

	int a = 10, b = 20, c = 30;
	std::cout <<"Result is: " << expression2(a, b, c);
}

int main()
{
	//HookJumpToPayload();
	//HookFromBeginWithPayLoad();
	HookFromMidWithPayload();
	getchar();
}

