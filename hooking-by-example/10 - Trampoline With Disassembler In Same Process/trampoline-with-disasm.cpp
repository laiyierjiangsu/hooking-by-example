/*
	This program demonstrates how to use an disassembler (in this case, the capstone library) to
	build trampolines for a function in a program WITHOUT having prior knowledge of the compiled
	assembly for that function.
*/

#include <stdio.h>
#include <cstdlib>
#include "capstone/x86.h"
#include "../hooking_common.h"
#include "capstone/capstone.h"
#include <vector>

__declspec(noinline) void TargetFunc(int x, float y)
{
	switch (x)
	{
		case 0: printf("0 args %f\n", y); break;
		case 1: printf("1 args %f\n", y); break;
		default:printf(">1 args\n"); break;
	}
}

_declspec(noinline) void CallTargetFunc(int x, float y)
{
	if (x > 0) CallTargetFunc(x - 1, y);
	TargetFunc(x, y);
	printf("Calling with x: %i y: %f \n", x, y);
}

void(*CallTargetFuncTrampoline)(int, float) = nullptr;
void HookPayload(int x, float y)
{
	printf("Hook Executed\n");

	//the function being hooked (CallTargetFunc) is recursive, so we need to make sure 
	//that we only replace the arguments for the first call in a sequence
	static int recurseGuard = 0;

	if (!recurseGuard)
	{
		recurseGuard = 1;
		CallTargetFuncTrampoline(2, y);
	}
	else
	{
		CallTargetFuncTrampoline(x, y);
	}
	recurseGuard = 0;
}

struct X64Instructions
{
	cs_insn* instructions;
	uint32_t numInstructions;
	uint32_t numBytes;
};

X64Instructions _StealBytes(void* function)
{
	// Disassemble stolen bytes
	csh handle;
	cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // we need details enabled for relocating RIP relative intrs

	size_t count;
	cs_insn* disassembledInstructions; //allocated by cs_disasm, needs to be manually freed later
	count = cs_disasm(handle, (uint8_t*)function, 20, (uint64_t)function, 20, &disassembledInstructions);

	//get the instructions covered by the first 5 bytes of the original function
	uint32_t byteCount = 0;
	uint32_t stolenInstrCount = 0;
	for (int32_t i = 0; i < count; ++i)
	{
		cs_insn& inst = disassembledInstructions[i];
		byteCount += inst.size;
		stolenInstrCount++;
		if (byteCount >= 5) break;
	}

	//replace stolen instructions in target func wtih NOPs, so that when we jump
	//back to the target function, we don't have to care about how many
	//bytes were stolen
	memset(function, 0x90, byteCount);

	cs_close(&handle);
	return { disassembledInstructions, stolenInstrCount, byteCount };
}

bool _IsRelativeJump(cs_insn& inst)
{
	bool isAnyJumpInstruction = inst.id >= X86_INS_JAE && inst.id <= X86_INS_JS;
	bool isJmp = inst.id == X86_INS_JMP;
	bool startsWithEBorE9 = inst.bytes[0] == 0xEB || inst.bytes[0] == 0xE9;
	return isJmp ? startsWithEBorE9 : isAnyJumpInstruction;
}

bool _IsRelativeCall(cs_insn& inst)
{
	bool isCall = inst.id == X86_INS_CALL;
	bool startsWithE8 = inst.bytes[0] == 0xE8;
	return isCall && startsWithE8;
}

template<class T>
T _GetDisplacement(cs_insn* inst, uint8_t offset)
{
	T disp;
	memcpy(&disp, &inst->bytes[offset], sizeof(T));
	return disp;
}

//rewrite instruction bytes so that any RIP-relative displacement operands
//make sense with wherever we're relocating to
void _RelocateInstruction(cs_insn* inst, void* dstLocation)
{
	cs_x86* x86 = &(inst->detail->x86);
	uint8_t offset = x86->encoding.disp_offset;

	uint64_t displacement = inst->bytes[x86->encoding.disp_offset];
	switch (x86->encoding.disp_size)
	{
		case 1:
		{
			int8_t disp = _GetDisplacement<uint8_t>(inst, offset);
			disp -= uint64_t(dstLocation) - inst->address;
			memcpy(&inst->bytes[offset], &disp, 1);
		}break;

		case 2:
		{
			int16_t disp = _GetDisplacement<uint16_t>(inst, offset);
			disp -= uint64_t(dstLocation) - inst->address;
			memcpy(&inst->bytes[offset], &disp, 2);
		}break;

		case 4:
		{
			int32_t disp = _GetDisplacement<int32_t>(inst, offset);
			disp -= (int32_t(dstLocation) - inst->address);
			memcpy(&inst->bytes[offset], &disp, 4);
		}break;
	}
}


//relative jump instructions need to be rewritten so that they jump to the appropriate
//place in the Absolute Instruction Table. Since we want to preserve any conditional
//jump logic, this func rewrites the instruction's operand bytes only. 
void _RewriteStolenJumpInstruction(cs_insn* instr, uint8_t* instrPtr, uint8_t* absTableEntry)
{
	uint8_t distToJumpTable = absTableEntry - (instrPtr + instr->size);

	//jmp instructions can have a 1 or 2 byte opcode, and need a 1-4 byte operand
	//rewrite the operand for the jump to go to the jump table
	uint8_t instrByteSize = instr->bytes[0] == 0x0F ? 2 : 1;
	uint8_t operandSize = instr->size - instrByteSize;

	switch (operandSize)
	{
	case 1: instr->bytes[instrByteSize] = distToJumpTable; break;
	case 2: {uint16_t dist16 = distToJumpTable; memcpy(&instr->bytes[instrByteSize], &dist16, 2); } break;
	case 4: {uint32_t dist32 = distToJumpTable; memcpy(&instr->bytes[instrByteSize], &dist32, 4); } break;
	}
}

//relative call instructions need to be rewritten as jumps to the appropriate
//plaec in the Absolute Instruction Table. Since we want to preserve the length
//of the call instruction, we first replace all the instruction's bytes with 1 byte
//NOPs, before writing a 2 byte jump to the start
void _RewriteStolenCallInstruction(cs_insn* instr, uint8_t* instrPtr, uint8_t* absTableEntry)
{
	uint8_t distToJumpTable = absTableEntry - (instrPtr + instr->size);

	//calls need to be rewritten as relative jumps to the abs table
	//but we want to preserve the length of the instruction, so pad with NOPs
	uint8_t jmpBytes[2] = { 0xEB, distToJumpTable };
	memset(instr->bytes, 0x90, instr->size);
	memcpy(instr->bytes, jmpBytes, sizeof(jmpBytes));
}

bool _IsRIPRelativeInstr(cs_insn& inst)
{
	cs_x86* x86 = &(inst.detail->x86);

	for (uint32_t i = 0; i < inst.detail->x86.op_count; i++)
	{
		cs_x86_op* op = &(x86->operands[i]);
		
		//mem type is rip relative, like lea rcx,[rip+0xbeef]
		if (op->type == X86_OP_MEM)
		{
			//if we're relative to rip
			return op->mem.base == X86_REG_RIP;
		}
	}

	return false;
}

uint32_t _AddJmpToAbsTable(cs_insn& jmp, uint8_t* absTableMem)
{
	char* targetAddrStr = jmp.op_str; //where the instruction intended to go
	uint64_t targetAddr = _strtoui64(targetAddrStr, NULL, 0);
	return WriteAbsoluteJump64(absTableMem, (void*)targetAddr);
}

uint32_t _AddCallToAbsTable(cs_insn& call, uint8_t* absTableMem, uint8_t* jumpBackToHookedFunc)
{
	char* targetAddrStr = call.op_str; //where the instruction intended to go
	uint64_t targetAddr = _strtoui64(targetAddrStr, NULL, 0);

	uint8_t* dstMem = absTableMem;

	uint8_t callAsmBytes[] =
	{
		0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //movabs 64 bit value into r10
		0x41, 0xFF, 0xD2, //call r10
	};
	memcpy(&callAsmBytes[2], &targetAddr, sizeof(void*));
	memcpy(dstMem, &callAsmBytes, sizeof(callAsmBytes));
	dstMem += sizeof(callAsmBytes);

	//after the call, we need to add a second 2 byte jump, which will jump back to the 
		//final jump of the stolen bytes
	uint8_t jmpBytes[2] = { 0xEB, jumpBackToHookedFunc - (absTableMem + sizeof(jmpBytes)) };
	memcpy(dstMem, jmpBytes, sizeof(jmpBytes));

	return sizeof(callAsmBytes) + sizeof(jmpBytes); //15
}

/*build a "jump - sandwich" style trampoline. This style of trampoline has three sections: 

		|----------------------------|
		|Stolen Instructions         |
		|----------------------------|
		|Jummp back to target func   |
		|----------------------------|
		|Absolute Instruction Table  |
		|----------------------------|
		
Relative instructions in the stolen instructions section need to be rewritten as absolute 
instructions which jump/call to the intended target address of those instructions (since they've
been relocated). Absolute versions of these instructions are added to the absolute instruction
table. The relative instruction in the stolen instructions section get rewritten to relative
jumps to the corresponding instructions in the absolute instruction table. 
*/
uint32_t _BuildTrampoline(void* func2hook, void* dstMemForTrampoline)
{
	X64Instructions stolenInstrs = _StealBytes(func2hook);

	uint8_t* stolenByteMem = (uint8_t*)dstMemForTrampoline;
	uint8_t* jumpBackMem = stolenByteMem + stolenInstrs.numBytes;
	uint8_t* absTableMem = jumpBackMem + 13; //13 is the size of a 64 bit mov/jmp instruction pair

	for (int i = 0; i < stolenInstrs.numInstructions; ++i)
	{
		cs_insn& inst = stolenInstrs.instructions[i];
		if (inst.id >= X86_INS_LOOP && inst.id <= X86_INS_LOOPNE)
		{
			return 0; //bail out on loop instructions, I don't have a good way of handling them 
		}

		if (_IsRelativeJump(inst))
		{
			uint32_t aitSize = _AddJmpToAbsTable(inst, absTableMem);
			_RewriteStolenJumpInstruction(&inst, stolenByteMem, absTableMem);
			absTableMem += aitSize;
		}
		else if (_IsRelativeCall(inst))
		{
			uint32_t aitSize = _AddCallToAbsTable(inst, absTableMem, jumpBackMem);
			_RewriteStolenCallInstruction(&inst, stolenByteMem, absTableMem);
			absTableMem += aitSize;
		}
		else if (_IsRIPRelativeInstr(inst)) 
		{
			//for instructions that use RIP relative address calculations like lea rcx,[rip + 0355h]
			_RelocateInstruction(&inst, stolenByteMem);
		}

		memcpy(stolenByteMem, inst.bytes, inst.size);
		stolenByteMem += inst.size;
	}

	WriteAbsoluteJump64(jumpBackMem, (uint8_t*)func2hook + 5);
	free(stolenInstrs.instructions);

	return absTableMem - dstMemForTrampoline;
}

void InstallHook(void* func2hook, void* payloadFunc, void** trampolinePtr)
{
	DWORD oldProtect;
	VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);

	//create the trampoline
	uint8_t trampolineBytes[1024];
	uint32_t trampolineSize = _BuildTrampoline(func2hook, trampolineBytes);

	//Allocate executable memory for the trampoline
	void* trampolineMem = VirtualAlloc(NULL, trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(trampolineMem, trampolineBytes, trampolineSize);
	*trampolinePtr = trampolineMem;

	//create the relay function
	void* relayFuncMemory = AllocatePageNearAddress(func2hook);
	WriteAbsoluteJump64(relayFuncMemory, payloadFunc); //write relay func instructions
	
	//install the hook
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
	const int32_t relAddr = (int32_t)relayFuncMemory - ((int32_t)func2hook + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);
	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));
}

int main(int argc, const char** argv)
{
	CallTargetFunc(5, argc);
	InstallHook(CallTargetFunc, HookPayload, (void**)&CallTargetFuncTrampoline);
	CallTargetFunc(7, (float)argc);
}

