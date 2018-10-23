#include "异常处理.h"
#include <stdio.h>
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include <Psapi.h>
#include "debugRegisters.h"
#include "BeaEngine_4.1\\Win32\\headers\\BeaEngine.h"
#include <TlHelp32.h>
#ifdef _WIN32
#pragma comment(lib,"BeaEngine_4.1\\Win32\\Win32\\Lib\\BeaEngine.lib")
#else
#pragma comment(lib, "BeaEngine_4.1/Win64/Win64/LibBeaEngine.lib")
#endif
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")
#pragma comment(lib, "legacy_stdio_definitions.lib")
//keystone头文件和静态库文件
#include "keystone/keystone.h"
#pragma comment (lib,"keystone/x86/keystone_x86.lib")

//一些全局变量
vector<ORIGIN_DATA> g_vecCoverData;
vector<DWORD> g_vecBreakPointByStepOver;
vector<HARD_BP> g_vecHardwareBreakPoint;
vector<MEM_BP> g_vecMemBreakPoint;
vector<string> g_vecInputString;
vector<MOD_INFO> g_vecModuleInfo;
vector<DWORD> g_vecConditionBp;
vector<SCRIPT> g_vectorRecord;
extern HANDLE g_hProcess;
extern HANDLE g_hThread;
extern HANDLE g_symHprocess;
extern int g_nChoice;
bool g_isSetByDbg = false;
bool g_hitTargetBp = false;
bool g_isConditionBp = false;
bool g_isRecordingScript = false;
bool g_isRunScript = false;
LPVOID g_plugin_fun = NULL;
LPVOID g_plugin_fun2 = NULL;



DWORD handleException(EXCEPTION_RECORD* pExceptionRecord)
{
	//在触发异常的时候,先不管三七二十一

	if (g_isSetByDbg)
	{
		//1.将保存的有int3断点的地址全部设置成CC,除了单步步过跳过call指令的
		renewAllInt3Bp();
		//2.将硬件断点全部更新到寄存器
		renewAllHardBp();
		//3.更新内存断点
		renewAllMemBp();
	}
	DWORD dwRet = DBG_CONTINUE;
	CONTEXT ct{ CONTEXT_CONTROL };
	switch (pExceptionRecord->ExceptionCode)
	{
	//异常类型是断点异常:int 3
	case EXCEPTION_BREAKPOINT:
	{
		//每个进程都有一个固定的系统断点
		static bool isSystemBreakpoint = true;
		if (isSystemBreakpoint) {
			isSystemBreakpoint = false;
			//给main函数下断点
			bpAtEntryPoint();
			//加载插件
			loadPlugin();
		}
		//如果不是系统断点,就恢复之前被CC覆盖的数据
		else {
			clearInt3BreakPoint(pExceptionRecord->ExceptionAddress);
			if (g_isConditionBp)
			{
				g_isConditionBp = false;
				goto EXIT;
			}
		}
	}
		break;
	//异常类型是访问权限异常
	case EXCEPTION_ACCESS_VIOLATION:
		//如果不是调试器主动触发的异常,则不作处理
		if (!handleMemExption(pExceptionRecord))
			dwRet = DBG_EXCEPTION_NOT_HANDLED;//好像少了点东西,这里如果返回了true
		if (g_hitTargetBp == false)
			goto EXIT;
		break;
	//异常类型是硬件断点或者TF标志位为1
	case EXCEPTION_SINGLE_STEP:
	{
		DWORD dwIndex = -1;
		if (g_isSetByDbg)
		{
			g_isSetByDbg = false;
			goto EXIT;
		}

		//判断是否是硬件断点(这里好像有问题)
		if ((dwIndex = isHardwareBP()) != -1)
		{
			//是硬件断点,在函数中处理
			//1.执行断点  2.访问断点   3.写断点
			handleHard_Bp(dwIndex);
		}
	}
		break;
	//调试器不做处理的异常
	default:
		dwRet = DBG_EXCEPTION_NOT_HANDLED;
		break;
	}
	//异常处理完毕
	//显示相关信息,如反汇编代码
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("获取线程上下文失败");
	}
	printDisasm(ct.Eip);

	//虽然异常处理完毕,由于当前函数还没有返回异常处理结果
	//现在T程序是处于中断状态
	//那么我们等待接收用户输入
	userInput(pExceptionRecord->ExceptionAddress);
EXIT:
	//默认返回调试器已处理异常,异常分发结束
	return dwRet;
}

void clearInt3BreakPoint(LPVOID pExceptionAddr)
{
	//找到待修改位置的原始数据,并替换CC
	int nIndex = 0;
	for (auto c: g_vecCoverData)
	{
		DWORD dwWritten = 0;
		if (c.originAddr == pExceptionAddr)
		{
			if (!WriteProcessMemory(g_hProcess, pExceptionAddr, &c.data, 1, &dwWritten))
			{
				DBG_EXIT("恢复断点失败!");
			}
			break;
		}
		nIndex++;
	}
	//判断此断点是否是一次性断点,如果是则从两张表中删除这个断点
	int nPos = 0;
	if (inVecStepoverBp((DWORD)pExceptionAddr, nPos))
	{
		g_vecBreakPointByStepOver.erase(g_vecBreakPointByStepOver.begin() + nPos);
		g_vecCoverData.erase(g_vecCoverData.begin() + nIndex);
	}

	//修改T进程断点所在线程的EIP的值,使其指向断点位置
	//否则EIP指向断点的下一条指令
	//CONTEXT_CONTROL==>传入不同的flag影响ct得到的寄存器的类型
	CONTEXT ct{ CONTEXT_ALL };
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("获取线程上下文失败");
	}
	ct.Eip--;
	if (!SetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("设置线程上下文失败");
	}
	//判断是否是条件断点,且是否满足条件
	if (inConditionTab(pExceptionAddr))
	{
		if (ct.Eax)
			g_isConditionBp = true;
		else
			g_isConditionBp = false;
	}
	else
		g_isConditionBp = false;
	//在这之通过修改TF标志位设置一个单步临时断点
	//以便在命中这个临时断点的时候重新将CC覆盖之前位置的数据
	//否则之前的断点为一次性断点
	setSingleStepBreakpoint();
	g_isSetByDbg = true;

}

void setSingleStepBreakpoint()
{
	CONTEXT ct{ CONTEXT_ALL };
	//获取线程上下文
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("获取线程上下文失败");
	}
	//将TF标志位置1
	EFLAGS* pEflags = (EFLAGS*)&ct.EFlags;
	pEflags->TF = 1;
	//再把线程上下文设置回去
	if (!SetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("设置线程上下文失败");
	}
}

void setInt3BreakPoint(LPVOID pointAddr)
{
	//首先读取该位置的数据
	ORIGIN_DATA od{};
	od.originAddr = pointAddr;
	DWORD beRead = 0, beWritten = 0;
	BYTE int3 = 0xCC;
	if (!ReadProcessMemory(g_hProcess, pointAddr, &od.data, 1, &beRead))DBG("下断点失败");
	//将该位置数据改为CC
	if(!WriteProcessMemory(g_hProcess, pointAddr, &int3, 1, &beWritten))DBG("下断点失败");
	//保存该位置的数据
	g_vecCoverData.push_back(od);
}

void printDisasm(DWORD eip, int nLen)
{
	DISASM da{};
	DWORD beRead = 0;
	char* opcode = new char[nLen * 15]{};
	if (!ReadProcessMemory(g_hProcess, (LPVOID)eip, opcode, nLen * 15, &beRead))
	{
		DBG_EXIT("读取opcode失败");
	}
	da.EIP = (UINT)opcode;
	da.VirtualAddr = eip;
#ifdef _WIN32
	da.Archi = 0;
#else
	da.Archi = 64;
#endif // _WIN32
	char* tempStr = new char[16]{};
	while (nLen--)
	{
		//得到已被反汇编的指令长度
		int retLen = Disasm(&da);
		//为-1表示找不到该指令对应的反汇编代码
		if (retLen == -1)break;
		//输出反汇编代码
		printf("%I64X | %s",
			da.VirtualAddr, da.CompleteInstr);
		//测试代码=================================================================================
		//分解汇编指令
		g_vecInputString = split(da.CompleteInstr, " ");
		CString strName;
		if (_stricmp(g_vecInputString[0].c_str(), "call") == 0)
		{
			if (g_vecInputString.size() == 2)
			{
				DWORD nNum = 0;
				int nNum2 = 0;
				strcpy(tempStr, g_vecInputString[1].c_str());
				sscanf(tempStr, "%08x", &nNum);
				sscanf(tempStr, "%d", &nNum2);
				if (nNum != 0 && nNum2 != 0)
				{
					if (GetSymName(g_symHprocess, (SIZE_T)nNum, strName))
					{
						printf(" ==> %S", strName.GetBuffer());
					}
				}
				else if (nNum2 == 0)
				{
					SIZE_T addr = getRegValue(tempStr);
					if (GetSymName(g_symHprocess, (SIZE_T)addr, strName))
					{
						printf(" ==> %S", strName.GetBuffer());
					}
				}
			}
			//call dword ptr [xxx]
			else if(g_vecInputString.size() == 4)
			{
				char filterChar = 0;
				DWORD addr = 0, realAddr = 0, dwRead = 0;
				sscanf(g_vecInputString[3].c_str(), "%c%08x", &filterChar, &addr);
				if (!ReadProcessMemory(g_hProcess, (LPVOID)addr, &realAddr, 4, &dwRead))
				{
					DBG("读取内存失败");
				}
				if (GetSymName(g_symHprocess, (SIZE_T)realAddr, strName))
				{
					printf(" ==> %S", strName.GetBuffer());
				}
			}
		}
		printf("\n");
		//测试代码=================================================================================
		da.VirtualAddr += retLen;
		da.EIP += retLen;
	}
	delete[] tempStr;
	delete[] opcode;
}

DWORD getNextCommandAddr(const DWORD& curCommandAddr, DWORD& nextCommandAddr)
{
	DWORD isCall = 0, beRead = 0;
	DISASM da{};
	if (!ReadProcessMemory(g_hProcess, (LPVOID)curCommandAddr, &isCall, 1, &beRead))
	{
		DBG_EXIT("读取T进程内存失败");
	}
	char* opcode = new char[15]{};
	if (!ReadProcessMemory(g_hProcess, (LPVOID)curCommandAddr, opcode, 15, &beRead))
	{
		DBG_EXIT("读取opcode失败");
	}
	da.EIP = (UINT)opcode;
	da.VirtualAddr = curCommandAddr;
#ifdef _WIN32
	da.Archi = 0;
#else
	da.Archi = 64;
#endif // _WIN32

	//得到已被反汇编的指令长度
	int retLen = Disasm(&da);
	//为-1表示找不到该指令对应的反汇编代码
	if (retLen == -1)nextCommandAddr = -1;
	else
	{
		nextCommandAddr = curCommandAddr + retLen;
	}
	delete[] opcode;
	opcode = NULL;
	return isCall;
}

void setHardwareBreakPoint(DWORD addr, int nType, int nByteLen)
{
	//1.判断DR0-DR3中是否有空闲寄存器
	CONTEXT ct{ CONTEXT_ALL };
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("获取线程上下文失败");
	}
	int nNum = whoIsFree();
	if (nNum == -1)
	{
		printf("下断失败,暂无空闲寄存器..\n");
		return;
	}
	//2.修改DR7寄存器对应字段的值
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	//inter推荐将LE和GE这两个字段置位
	pDr7->LE = 1;
	pDr7->GE = 1;
	switch (nNum)
	{
	//DR0有空
	case 0:
		if (nType == 0 || nByteLen == 0)
			ct.Dr0 = addr;
		else
		{
			//两字节断点
			if(nByteLen == 1)
				ct.Dr0 = addr - addr % 2;
			//四字节断点
			else
				ct.Dr0 = addr - addr % 4;
		}
			
		pDr7->L0 = 1;
		pDr7->RW0 = nType;
		pDr7->LEN0 = nByteLen;
		break;
	//DR1有空
	case 1:
		if (nType == 0 || nByteLen == 0)
			ct.Dr1 = addr;
		else
		{
			//两字节断点
			if (nByteLen == 1)
				ct.Dr1 = addr - addr % 2;
			//四字节断点
			else
				ct.Dr1 = addr - addr % 4;
		}
		pDr7->L1 = 1;
		pDr7->RW1 = nType;
		pDr7->LEN1 = nByteLen;
		break;
	//DR2有空
	case 2:
		if (nType == 0 || nByteLen == 0)
			ct.Dr2 = addr;
		else
		{
			//两字节断点
			if (nByteLen == 1)
				ct.Dr2 = addr - addr % 2;
			//四字节断点
			else
				ct.Dr2 = addr - addr % 4;
		}
		pDr7->L2 = 1;
		pDr7->RW2 = nType;
		pDr7->LEN2 = nByteLen;
		break;
	//DR3有空
	case 3:
		if (nType == 0 || nByteLen == 0)
			ct.Dr3 = addr;
		else
		{
			//两字节断点
			if (nByteLen == 1)
				ct.Dr3 = addr - addr % 2;
			//四字节断点
			else
				ct.Dr3 = addr - addr % 4;
		}
		pDr7->L3 = 1;
		pDr7->RW3 = nType;
		pDr7->LEN3 = nByteLen;
		break;
	default:
		//printf("下断失败,暂无空闲寄存器..\n");
		return;
	}
	
	//3.将上下文设置回去
	if (!SetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("设置线程上下文失败");
	}
	//4.保存断点记录
	HARD_BP hb{};
	hb.bpAddr = (LPVOID)addr;
	hb.reg = nNum;
	hb.type = nType;
	g_vecHardwareBreakPoint.push_back(hb);
}
int whoIsFree()
{
	//获取DR0-DR3的值
	if (!getRegValue("dr0"))return 0;
	else if (!getRegValue("dr1"))return 1;
	else if (!getRegValue("dr2"))return 2;
	else if (!getRegValue("dr3"))return 3;
	return -1;
}
DWORD getRegValue(char* regName)
{
	DWORD dwRet = -1;
	CONTEXT ct{ CONTEXT_ALL };
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("获取线程上下文失败");
	}
	if (_stricmp(regName, "eax") == 0) {
		dwRet = ct.Eax;
	}
	else if (_stricmp(regName, "ebx") == 0) {
		dwRet = ct.Ebx;
	}
	else if (_stricmp(regName, "ecx") == 0) {
		dwRet = ct.Ecx;
	}
	else if (_stricmp(regName, "edx") == 0) {
		dwRet = ct.Edx;
	}
	else if (_stricmp(regName, "esi") == 0) {
		dwRet = ct.Esi;
	}
	else if (_stricmp(regName, "edi") == 0) {
		dwRet = ct.Edi;
	}
	else if (_stricmp(regName, "esp") == 0) {
		dwRet = ct.Esp;
	}
	else if (_stricmp(regName, "ebp") == 0) {
		dwRet = ct.Ebp;
	}
	else if (_stricmp(regName, "eflags") == 0) {
		dwRet = ct.EFlags;
	}
	else if (_stricmp(regName, "eip") == 0) {
		dwRet = ct.Eip;
	}
	else if (_stricmp(regName, "dr0") == 0) {
		dwRet = ct.Dr0;
	}
	else if (_stricmp(regName, "dr1") == 0) {
		dwRet = ct.Dr1;
	}
	else if (_stricmp(regName, "dr2") == 0) {
		dwRet = ct.Dr2;
	}
	else if (_stricmp(regName, "dr3") == 0) {
		dwRet = ct.Dr3;
	}
	else if (_stricmp(regName, "dr6") == 0) {
		dwRet = ct.Dr6;
	}
	else if (_stricmp(regName, "dr7") == 0) {
		dwRet = ct.Dr7;
	}
	else if (_stricmp(regName, "cs") == 0) {
		dwRet = ct.SegCs;
	}
	else if (_stricmp(regName, "ds") == 0) {
		dwRet = ct.SegDs;
	}
	else if (_stricmp(regName, "fs") == 0) {
		dwRet = ct.SegFs;
	}
	else if (_stricmp(regName, "gs") == 0) {
		dwRet = ct.SegGs;
	}
	else if (_stricmp(regName, "cs") == 0) {
		dwRet = ct.SegCs;
	}
	else if (_stricmp(regName, "es") == 0) {
		dwRet = ct.SegEs;
	}
	else if (_stricmp(regName, "ss") == 0) {
		dwRet = ct.SegSs;
	}
	return dwRet;
}
//DWORD isHardwareBP(LPVOID pointAddr)
//{
//	DWORD dwRet = -1;
//	for (auto i : g_vecHardwareBreakPoint)
//	{
//		int index = 0;
//		if ((DWORD)i.bpAddr == (DWORD)pointAddr)
//		{
//			return index;
//		}
//		index++;
//	}
//	return dwRet;
//}
//DWORD isHardwareBP(EXCEPTION_RECORD* pExpRcd)
//{
//	DWORD dwRet = -1;
//	for (auto i : g_vecHardwareBreakPoint)
//	{
//		int index = 0;
//		//需要判断硬件断点表中的类型
//		//1.如果是执行断点,直接用pExpRcd中的异常地址与i.addr比较就行了
//		//2.如果是读写断点,则需要用pExcRcd中的information[1]和i.addr比较
//		switch (i.type)
//		{
//		case 0:
//			if ((DWORD)i.bpAddr == (DWORD)pExpRcd->ExceptionAddress)
//			{
//				return index;
//			}
//			break;
//		case 1:
//		case 3:
//			if ((DWORD)i.bpAddr == (DWORD)pExpRcd->ExceptionInformation[1])
//			{
//				return index;
//			}
//			break;
//		}
//		index++;
//	}
//	return dwRet;
//}
DWORD isHardwareBP()
{
	DWORD dwRet = -1;
	CONTEXT ct{ CONTEXT_ALL };
	GetThreadContext(g_hThread, &ct);
	DBG_REG6* pDr6 = (DBG_REG6*)&ct.Dr6;
	if (pDr6->B0)return 0;
	else if (pDr6->B1)return 1;
	else if (pDr6->B2)return 2;
	else if (pDr6->B3)return 3;
	return dwRet;
}
void handleHard_Bp(DWORD nIndex)
{
	CONTEXT ct{ CONTEXT_ALL };
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("获取线程上下文失败");
	}
	//得到当前硬件断点结构体信息
	HARD_BP curStcBpInfo = g_vecHardwareBreakPoint[nIndex];
	//1.判断是何种类型的硬件断点,写,读写,或者执行
	switch (curStcBpInfo.type)
	{
	//2.修改相应的寄存器的值
	case 0:		//执行断点
	{
		//当前EIP的位置指向断点位置,因此需要将该断点临时清除,不然程序无法继续执行
		DBG_REG6* pDr6 = (DBG_REG6*)&ct.Dr6;
		DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
		switch (curStcBpInfo.reg)
		{
		case 0:
			ct.Dr0 = 0;
			pDr7->L0 = 0;
			break;
		case 1:
			ct.Dr1 = 0;
			pDr7->L1 = 0;
			break;
		case 2:
			ct.Dr2 = 0;
			pDr7->L2 = 0;
			break;
		case 3:
			ct.Dr3 = 0;
			pDr7->L3 = 0;
			break;
		}
	}
		break;
	case 1:		//写断点,对于写断点和访问断点:该条指令已被执行,eip指向断点下一条指令
	case 3:		//访问断点,对于写断点和访问断点:该条指令已被执行,eip指向断点下一条指令
		//两者操作一致,但在这之后显示反汇编代码就显示的是EIP的位置,断点位置的反汇编代码就显示不出来了
		break;
	default:
		break;
	}
	//3.将上下文设置回去
	if (!SetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("设置线程上下文失败");
	}
	//4.设置单步TF断点,以便执行一步之后恢复硬件断点寄存器的值
	setSingleStepBreakpoint();
	g_isSetByDbg = true;
}
void renewAllHardBp()
{
	CONTEXT ct{ CONTEXT_ALL };
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("获取线程上下文失败");
	}
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	for(auto i: g_vecHardwareBreakPoint)
	{
		switch (i.reg)
		{
		case 0:
			ct.Dr0 = (DWORD)i.bpAddr;
			pDr7->L0 = 1;
			pDr7->RW0 = i.type;
			break;
		case 1:
			ct.Dr1 = (DWORD)i.bpAddr;
			pDr7->L1 = 1;
			pDr7->RW1 = i.type;
			break;
		case 2:
			ct.Dr2 = (DWORD)i.bpAddr;
			pDr7->L2 = 1;
			pDr7->RW2 = i.type;
			break;
		case 3:
			ct.Dr3 = (DWORD)i.bpAddr;
			pDr7->L3 = 1;
			pDr7->RW3 = i.type;
			break;
		default:
			break;
		}
	}
	if (!SetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("设置线程上下文失败");
	}
}
void showCurReg()
{
	CONTEXT ct{ CONTEXT_ALL };
	//SuspendThread(g_hThread);
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("获取线程上下文失败");
	}
	//ResumeThread(g_hThread);
	printf("	eax: %08X\tebx: %08X\tecx: %08X\tedx: %08X\n\
	esi: %08X\tedi: %08X\tesp: %08X\tebp: %08X\n\
	eip: %08X\teflags: %08X\n\
	cs: %08X\tds: %08X\tes: %08X\tss: %08X\n\
	fs: %08X\tgs: %08X\n\
	dr0: %08X\tdr1: %08X\tdr2: %08X\n\
	dr3: %08X\tdr6: %08X\tdr7: %08X\n",
	ct.Eax, ct.Ebx, ct.Ecx, ct.Edx, ct.Esi, ct.Edi, ct.Esp, ct.Ebp, ct.Eip, ct.EFlags, ct.SegCs, ct.SegDs, ct.SegEs, ct.SegSs, ct.SegFs, ct.SegGs,
	ct.Dr0, ct.Dr1, ct.Dr2, ct.Dr3, ct.Dr6, ct.Dr7);
	
}

void renewAllInt3Bp()
{
	//用CC重新覆盖断点位置数据
	DWORD dwWritten = 0;
	for (auto c : g_vecCoverData)
	{
		if (!WriteProcessMemory(g_hProcess, c.originAddr, "\xCC", 1, &dwWritten))
		{
			DBG_EXIT("恢复断点失败");
		}
	}
}
void userInput(LPVOID pExpAddr)
{
	while (1)
	{
		printf("命令>>");
		char szCmd[32]{};
		if (g_isRunScript == false)
		{
			while (!strlen(szCmd))
				gets_s(szCmd, _countof(szCmd));
		}
		else
		{
			Sleep(1500);
			static HANDLE hFile = CreateFileA("script.txt", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
			strcpy(szCmd, getCommand(hFile));
			if (_stricmp("over", szCmd) == 0)
			{
				printf("\n--------------------------\n脚本运行完毕\n--------------------------\n");
				g_isRunScript = false;
				memset(szCmd, 1, 32);
			}
			else
				printf("%s\n", szCmd);
		}
		if (g_isRecordingScript)
		{
			SCRIPT s{};
			memcpy(s.operate, szCmd, 32);
			g_vectorRecord.push_back(s);
		}
		g_vecInputString.clear();
		g_vecInputString = split(szCmd, " ");
		//如果是"g"命令,我们直接给T进程放行(VS的F5)
		if (_stricmp(szCmd, "g") == 0)
		{
			break;
		}
		//如果是"t"命令,表示单步步人(VS的F11)
		else if (_stricmp(szCmd, "t") == 0)
		{
			//设置一个单步断点
			setSingleStepBreakpoint();
			g_isSetByDbg = false;
			break;
		}
		//如果是"p"命令,表示单步步过(VS的F10)
		else if (_stricmp(szCmd, "p") == 0)
		{

			//如果当前指令是call指令,则在下一条指令位置下一个int 3断点
			//否则当成"t"命令处理
			//这一个断点是一次性的,因此不需要在步过后被恢复
			//获取下一条指令的地址
			DWORD nextCommandAddr = 0;
			DWORD isCall = getNextCommandAddr((DWORD)pExpAddr, nextCommandAddr);
			if (isCall == 0xE8 || isCall == 0x9A || isCall == 0xF2 || isCall == 0xF3)
			{
				if (nextCommandAddr != -1)
				{
					setInt3BreakPoint((LPVOID)nextCommandAddr);
					g_vecBreakPointByStepOver.push_back(nextCommandAddr);
				}
			}
			else
			{
				setSingleStepBreakpoint();
				g_isSetByDbg = false;
			}
			break;
		}
		//如果是"ret"命令, 运行到返回
		else if (_stricmp(szCmd, "ret") == 0)
		{
			runToRet();
			break;
		}
		//如果是"bp"命令,表示在某行设置断点
		else if (_stricmp(szCmd, "bp") == 0)
		{
			//再接收一个需要下断点的地址
			printf("下断地址>>");
			DWORD pointAddr = 0;
			scanf_s("%x", &pointAddr);
			setInt3BreakPoint((LPVOID)pointAddr);
			while (getchar() != '\n');
		}
		else if (_stricmp(szCmd, "bl") == 0)
		{
			//查询所有断点
			int nIndex = 1;
			for (auto c : g_vecCoverData)
			{
				printf("%d  ==>  %08X\n", nIndex, (DWORD)c.originAddr);
				nIndex++;
			}

		}
		//如果是"he"命令,表示下硬件执行断点
		else if (_stricmp(szCmd, "he") == 0)
		{
			//再接收一个需要下断点的地址
			printf("下断地址>>");
			DWORD pointAddr = 0;
			scanf_s("%x", &pointAddr);
			//设置一个执行断点
			setHardwareBreakPoint(pointAddr);
			while (getchar() != '\n');
		}
		//如果是"hw"命令,表示下硬件写断点
		else if (_stricmp(szCmd, "hw") == 0)
		{
			//再接收一个需要下断点的地址
			printf("下断地址 & 数据长度类型(0,1,3)>>");
			DWORD pointAddr = 0, nLen = 0;
			scanf_s("%x %d", &pointAddr, &nLen);
			if (nLen != 0 && nLen != 1 && nLen != 3)
				printf("不接受断点数据长度: %d\n", nLen);
			//设置一个硬件写断点
			else
				setHardwareBreakPoint(pointAddr, 1, nLen);
			while (getchar() != '\n');
		}//来了
		//如果是"mr"命令,表示下内存访问断点
		else if (_stricmp(szCmd, "mr") == 0)
		{
			//再接收一个需要下断点的地址
			printf("下断地址>>");
			DWORD pointAddr = 0;
			scanf_s("%x", &pointAddr);

			//设置一个内存访问断点
			setMemBreakPoint(pointAddr);
			while (getchar() != '\n');
		}
		//硬件访问断点
		else if (_stricmp(szCmd, "hr") == 0)
		{
			//再接收一个需要下断点的地址
			printf("下断地址 & 数据长度类型(0,1,3)>>");
			DWORD pointAddr = 0, nLen = 0;
			scanf_s("%x %d", &pointAddr, &nLen);
			if (nLen != 0 && nLen != 1 && nLen != 3)
				printf("不接受断点数据长度: %d\n", nLen);
			//设置一个硬件访问断点
			else
				setHardwareBreakPoint(pointAddr, 3, nLen);
			while (getchar() != '\n');
		}
		//查看T进程寄存器
		else if (_stricmp(szCmd, "r") == 0)
		{
			showCurReg();
		}
		//查看内存
		else if (_stricmp(szCmd, "dd") == 0)
		{
			//再接收一个需要读内存的地址
			printf("地址>>");
			DWORD memAddr = 0;
			scanf_s("%x", &memAddr);
			while (getchar() != '\n');
			showMem(memAddr);
		}
		else if (_stricmp(g_vecInputString[0].c_str(), "dd") == 0 && g_vecInputString.size() == 2)
		{
			showMem2();
		}
		//查看栈
		else if (_stricmp(szCmd, "ds") == 0)
		{
			showStack();
		}
		//修改寄存器
		else if (_stricmp(g_vecInputString[0].c_str(), "r") == 0 && g_vecInputString.size() == 3)
		{
			editReg();
		}
		//修改内存数据
		else if (_stricmp(g_vecInputString[0].c_str(), "m") == 0 && g_vecInputString.size() == 3)
		{
			editMem();
		}
		//查看汇编代码
		else if (_stricmp(g_vecInputString[0].c_str(), "u") == 0 && g_vecInputString.size() == 2)
		{
			CONTEXT ct{ CONTEXT_ALL };
			if (!GetThreadContext(g_hThread, &ct))
			{
				DBG_EXIT("获取线程环境失败");
			}
			DWORD eip = ct.Eip;
			int nLen = 0;
			sscanf(g_vecInputString[1].c_str(), "%d", &nLen);
			printDisasm(eip, nLen);
		}
		//查看指定地址的汇编代码
		else if (_stricmp(g_vecInputString[0].c_str(), "ua") == 0 && g_vecInputString.size() == 2)
		{
			DWORD addr = 0;
			sscanf(g_vecInputString[1].c_str(), "%x", &addr);
			printDisasm(addr);
		}
		//修改反汇编代码
		else if (_stricmp(g_vecInputString[0].c_str(), "ue") == 0 && g_vecInputString.size() == 2)
		{
			editDisasmCode();
		}
		//显示模块信息
		else if (_stricmp(szCmd, "mod") == 0)
		{
			showModule();
		}
		//显示源代码
		else if (_stricmp(szCmd, "l") == 0)
		{
			cppDebug();
		}
		//清除int3断点
		else if (_stricmp(g_vecInputString[0].c_str(), "bc") == 0)
		{
			clearBreakPoint();
		}
		//peb隐藏
		else if (_stricmp(g_vecInputString[0].c_str(), "hide") == 0)
		{
			clearProtect();
		}
		//API断点
		else if (_stricmp(szCmd, "api") == 0)
		{
			setApiBp();
		}
		//显示模块导入导出表
		else if (_stricmp(szCmd, "tab") == 0)
		{
			showModuleExportTable();
			while (getchar() != '\n');
		}
		//使用插件函数
		else if (_stricmp(szCmd, "pf") == 0)
		{
			_asm call g_plugin_fun;
		}
		else if (_stricmp(szCmd, "pf2") == 0)
		{
			_asm call g_plugin_fun2;
		}
		//设置条件断点
		else if (g_vecInputString.size() == 2 && _stricmp(g_vecInputString[0].c_str(), "bp") == 0)
		{
			setConditionBp((DWORD)pExpAddr);
		}
		//清除内存断点
		else if (_stricmp(g_vecInputString[0].c_str(), "bcm") == 0)
		{
			clearMemBp();
		}
		//清除硬件断点
		else if (_stricmp(g_vecInputString[0].c_str(), "bch") == 0)
		{
			clearHardwareBp();
		}
		//dump指定内存内容
		else if (_stricmp(szCmd, "dmp") == 0)
		{
			printf("起始地址 & 大小>>");
			DWORD startAddr = 0, nSize = 0;
			scanf("%x %x", &startAddr, &nSize);
			dumpMemInfo(startAddr, nSize);
			while (getchar() != '\n');
		}
		//miniDump
		else if (_stricmp(szCmd, "mdmp") == 0)
		{
			miniDump(NULL);
		}
		//开始录制脚本
		else if (_stricmp(szCmd, "start") == 0)
		{
			recordScript();
		}
		//结束录制脚本
		else if (_stricmp(szCmd, "over") == 0)
		{
			recordOver();
		}
		else if (_stricmp(szCmd, "run") == 0)
		{
			runScript();
		}
	}
}
void showMem(DWORD memAddr)
{
	DWORD dwData = 0, dwRead = 0;
	for (int i = 0; i < 16; i++)
	{
		if (i % 4 == 0)
		{
			printf("%08x   |", memAddr);
		}
		if (!ReadProcessMemory(g_hProcess, (LPVOID)memAddr, &dwData, 4, &dwRead))
		{
			DBG("无效地址");
			break;
		}
		else
		{
			printf("%08x  ", dwData);
			if ((i + 1) % 4 == 0)
			{
				printf("\n");
			}
		}
		memAddr += 4;
	}
}
void setMemBreakPoint(DWORD memBpAddr)
{
	MEM_BP mb{};
	mb.bpAddr = memBpAddr;
	mb.pageBaseAddr = memBpAddr - memBpAddr % 0x1000;
	//先将这个分页的属性改为没有权限
	if (!VirtualProtectEx(g_hProcess,(LPVOID)memBpAddr, 1, PAGE_NOACCESS, &mb.oldPageAttribute))
	{
		DBG("修改分页属性失败");
		return;
	}
	if (mb.oldPageAttribute != PAGE_READWRITE && mb.oldPageAttribute != PAGE_EXECUTE_READWRITE 
		&& mb.oldPageAttribute != PAGE_EXECUTE_WRITECOPY)
	{
		DBG("该分页无内存写入属性");
		//恢复分页属性
		VirtualProtectEx(g_hProcess,(LPVOID)memBpAddr, 1, mb.oldPageAttribute, &mb.oldPageAttribute);
		return;
	}
	//否则下断成功,记录内存断点相关属性
	g_vecMemBreakPoint.push_back(mb);
}
bool handleMemExption(EXCEPTION_RECORD* pExceptionRecord)
{
	//1.判断异常地址分页是否是用户下的内存访问断点所在分页
	bool isSetByUser = false;
	for (auto i : g_vecMemBreakPoint)
	{
		if (i.pageBaseAddr == (pExceptionRecord->ExceptionInformation[1] - pExceptionRecord->ExceptionInformation[1] % 0x1000))
		{
			isSetByUser = true;			
			DWORD old = 0;
			if (!VirtualProtectEx(g_hProcess, (LPVOID)i.bpAddr, 1, i.oldPageAttribute, &old))
			{
				DBG("恢复分页属性失败");
			}
			setSingleStepBreakpoint();
			g_isSetByDbg = true;
			//2.判断该地址是否正好是用户下断点的地址
			//不是目标断点
			if (i.bpAddr != (DWORD)pExceptionRecord->ExceptionInformation[1])//这里比较的内容错了,ExceptionAddress这是指令的地址,不是内存权限不够的内存地址,改用这个ExceptionInformation[1]
			{
				g_hitTargetBp = false;
				break;
			}
			//命中目标断点
			else
			{
				g_hitTargetBp = true;
				break;
			}
		}
	}
	//
	return isSetByUser;
}
void renewAllMemBp()
{
	for (auto i : g_vecMemBreakPoint)
	{
		DWORD old = 0;
		if (!VirtualProtectEx(g_hProcess, (LPVOID)i.bpAddr, 1, PAGE_NOACCESS, &old))
		{
			DBG("修改分页属性失败");
		}
	}
}
void showStack()
{
	DWORD esp = getRegValue("esp");
	DWORD ebp = getRegValue("ebp");
	DWORD dwRead = 0;
	char* szBuf = new char[ebp - esp];
	if (!ReadProcessMemory(g_hProcess, (LPVOID)esp, szBuf, ebp - esp, &dwRead))
	{
		DBG("获取堆栈信息失败");
		return;
	}
	//获取十条信息
	if ((ebp - esp) / 4 > 10)
	{
		for (int i = 0; i < 10; i++)
		{
			printf("%08x   | %08x\n", esp + i * 4, *(DWORD*)(szBuf + i * 4));
		}
	}
	else
	{
		for (DWORD i = 0; i < (ebp - esp) / 4; i++)
		{
			printf("%08x   | %08x\n", esp + i * 4, *(DWORD*)(szBuf + i * 4));
		}
	}
	delete[] szBuf;
}
vector<string> split(const string &str, const string &pattern)
{
	//const char* convert to char*
	char * strc = new char[strlen(str.c_str()) + 1];
	strcpy(strc, str.c_str());
	vector<string> resultVec;
	char* tmpStr = strtok(strc, pattern.c_str());
	while (tmpStr != NULL)
	{
		resultVec.push_back(string(tmpStr));
		tmpStr = strtok(NULL, pattern.c_str());
	}
	delete[] strc;
	return resultVec;
}
void editReg()
{
	CONTEXT ct{ CONTEXT_ALL };
	DWORD nNum = 0;
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG("获取线程上下文失败");
		return;
	}
	if (_stricmp("eax", g_vecInputString[1].c_str()) == 0)
	{
		sscanf(g_vecInputString[2].c_str(), "%08X", &nNum);
		ct.Eax = nNum;
	}
	else if (_stricmp("ebx", g_vecInputString[1].c_str()) == 0)
	{
		sscanf(g_vecInputString[2].c_str(), "%08X", &nNum);
		ct.Ebx = nNum;
	}
	else if (_stricmp("ecx", g_vecInputString[1].c_str()) == 0)
	{
		sscanf(g_vecInputString[2].c_str(), "%08X", &nNum);
		ct.Ecx = nNum;
	}
	else if (_stricmp("edx", g_vecInputString[1].c_str()) == 0)
	{
		sscanf(g_vecInputString[2].c_str(), "%08X", &nNum);
		ct.Edx = nNum;
	}
	else if (_stricmp("eip", g_vecInputString[1].c_str()) == 0)
	{
		sscanf(g_vecInputString[2].c_str(), "%08X", &nNum);
		ct.Eip = nNum;
	}
	if (!SetThreadContext(g_hThread, &ct))
	{
		DBG("获取线程上下文失败");
		return;
	}
}
void editMem()
{
	DWORD memAddr = 0;
	DWORD memData = 0;
	DWORD dwWrite = 0;
	
	if (_stricmp("ebp", g_vecInputString[1].c_str()) == 0)
	{
		memAddr = getRegValue("ebp");
	}
	else if (_stricmp("esp", g_vecInputString[1].c_str()) == 0)
	{
		memAddr = getRegValue("esp");
	}
	sscanf(g_vecInputString[2].c_str(), "%08X", &memData);
	if (!WriteProcessMemory(g_hProcess, LPVOID(memAddr), (LPVOID)&memData, 4, &dwWrite))
	{
		DBG("修改内存失败");
	}
}
void showMem2()
{
	DWORD memAddr = 0, dwRead = 0;
	char szbuf[64]{};
	if (_stricmp("ebp", g_vecInputString[1].c_str()) == 0)
	{
		memAddr = getRegValue("ebp");
	}
	else if (_stricmp("eax", g_vecInputString[1].c_str()) == 0)
	{
		memAddr = getRegValue("eax");
	}
	else if (_stricmp("ebx", g_vecInputString[1].c_str()) == 0)
	{
		memAddr = getRegValue("ebx");
	}
	else if (_stricmp("ecx", g_vecInputString[1].c_str()) == 0)
	{
		memAddr = getRegValue("ecx");
	}
	else if (_stricmp("edx", g_vecInputString[1].c_str()) == 0)
	{
		memAddr = getRegValue("edx");
	}
	else if (_stricmp("esp", g_vecInputString[1].c_str()) == 0)
	{
		memAddr = getRegValue("esp");
	}
	if (!ReadProcessMemory(g_hProcess, (LPVOID)memAddr, szbuf, 64, &dwRead))
	{
		DBG("读取内存失败");
		return;
	}
	for (int i = 0; i < 16; i++)
	{
		if (i % 4 == 0)
		{
			printf("%08x   |", memAddr + i * 4);
		}
		printf("%08x  ", *(DWORD*)(szbuf + i * 4));
		if ((i + 1) % 4 == 0)
		{
			printf("\n");
		}
	}
}
void showModule()
{
	MOD_INFO record;
	HMODULE hMod[1024]{};
	DWORD dwNeeded = 0;
	MODULEINFO mi{};
	char szBuff[MAX_PATH]{};
	if (!EnumProcessModules(g_hProcess, hMod, sizeof(hMod), &dwNeeded))
	{
		DBG_EXIT("枚举进程模块失败");
	}
	DWORD dwRealSize = dwNeeded / sizeof(HMODULE);
	for (DWORD i = 0; i < dwRealSize; i++)
	{
		if (!GetModuleInformation(g_hProcess, hMod[i], &mi, sizeof(mi)))
		{
			DBG("获取模块信息失败");
		}
		GetModuleFileNameExA(g_hProcess, hMod[i], szBuff, MAX_PATH);
		printf("加载基址:%08X          模块名:%s\n", (DWORD)mi.lpBaseOfDll, szBuff);
		record.dllImageBase = (DWORD)mi.lpBaseOfDll;
		strcpy(record.dllName, szBuff);
		g_vecModuleInfo.push_back(record);
	}
}
void onLoadExeSymbol(CREATE_PROCESS_DEBUG_INFO *pInfo)
{
	g_symHprocess = g_hProcess;
	if (SymInitialize(g_symHprocess, "D:\\c代码\\ClassTest\\Debug\\class.pdb", false))
	{
		DWORD64 moduleAddr = SymLoadModule64(g_hProcess, pInfo->hFile, 0, 0, (DWORD64)pInfo->lpBaseOfImage, 0);
		if (!moduleAddr)
		{
			DBG("加载符号调试信息失败");
		}
	}
	
	CloseHandle(pInfo->hFile);
	CloseHandle(pInfo->hThread);
	CloseHandle(pInfo->hProcess);
}
void onLoadDllSymbol(LOAD_DLL_DEBUG_INFO *pInfo)
{
	DWORD64 moduleAddr = SymLoadModule64(g_symHprocess, pInfo->hFile, 0, 0, (DWORD64)pInfo->lpBaseOfDll, 0);
	if (!moduleAddr)
	{
		DBG("加载符号调试信息失败");
	}
	CloseHandle(pInfo->hFile);
}
void cppDebug()
{
	CONTEXT ct{ CONTEXT_ALL };
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG("获取线程上下文失败");
		return;
	}
	DWORD displacement = 0;
	IMAGEHLP_LINE64 pl{};
	pl.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

	//根据汇编代码地址获取行号,行号保存在pl的LineNumber中
	//就是这个函数,然后会给我源文件名和汇编代码对应的源代码所在的行.
	
	if (!SymGetLineFromAddr64(g_symHprocess, ct.Eip, &displacement, &pl))
	{
		DBG("获取信息失败");
		return;
	}
	//根据行号获取行地址
	IMAGEHLP_LINE64 lineAddr{};
	lineAddr.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
	//这个偏移用来判断当前行是否为有效行(编译过后有汇编代码),为0则有效
	LONG offset = 0;
	BOOL b = SymGetLineFromName64(g_symHprocess, 0, pl.FileName, pl.LineNumber, &offset, &lineAddr);
	int lineNumber = pl.LineNumber;
	while (1)
	{
		if (offset == 0)
		{
			char* szContent = readLine(pl.FileName, lineNumber);
			if (szContent)
			{
				printf("%08x  | %s\n", (DWORD)lineAddr.Address, szContent);
			}
		}
		lineNumber++;
		SymGetLineFromName64(g_symHprocess, 0, "D:\\c代码\\ClassTest\\class\\main.cpp", lineNumber, &offset, &lineAddr);
		if (offset > 5 )break;
	}

	//char buff[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)]{};
	//PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buff;
	//pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	//pSymbol->MaxNameLen = MAX_SYM_NAME;
	//if (!SymFromAddr(g_symHprocess, pltt.Address, (DWORD64*)&displacement, pSymbol))
	//	return;
	//char* strName = pSymbol->Name;
	//int ii = 0;
}
 void bpAtEntryPoint() {

	 static char* entryPointNames[] = {
		"main",
		"wmain",
		"WinMain",
		"wWinMain",
	 };

	 SYMBOL_INFO symbolInfo = { 0 };
	 symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);

	 for (int index = 0; index != sizeof(entryPointNames) / sizeof(LPCTSTR); ++index) {

		 if (SymFromName(g_symHprocess, entryPointNames[index], &symbolInfo) == TRUE) {
			 setInt3BreakPoint((LPVOID)symbolInfo.Address);
		 }
	 }
 }
 char* readLine(char* szPath, int nLine)
 {
	 FILE* fpfile = NULL;
	 if (fopen_s(&fpfile, szPath, "rb"))
	 {
		 return NULL;
	 }
	 char* buff = new char[MAX_PATH];
	 while (nLine--)
	 {
		 if (feof(fpfile))
		 {
			 return NULL;
		 }
		 memset(buff, 0, MAX_PATH);
		 fgets(buff, MAX_PATH, fpfile);
	 }
	 fclose(fpfile);
	 return buff;
 }

 BOOL GetSymName(HANDLE hProcee, SIZE_T nAddress, CString& strName)
 {
	 DWORD64 displacement = 0;
	 char buff[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)]{};
	 PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buff;
	 pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	 pSymbol->MaxNameLen = MAX_SYM_NAME;
	 if (!SymFromAddr(g_symHprocess, nAddress, &displacement, pSymbol))
		 return FALSE;
	 strName = pSymbol->Name;
	 int ii = 0;
	 return TRUE;
 }
 void clearBreakPoint()
 {
	 DWORD dwWritten = 0;
	 //删除所有断点
	 int nPos = 0;
	 if (g_vecInputString.size() == 1)
	 {
		 //除了通过STEPOVER设置的int3断点,其他的全部恢复原始数据并删除
		 for (auto i = g_vecCoverData.begin(); i != g_vecCoverData.end();)
		 {
			 //不是通过STEPOVER设置的int3断点
			 if (!inVecStepoverBp((DWORD)i->originAddr, nPos))
			 {
				 if (!WriteProcessMemory(g_hProcess, i->originAddr, &i->data, 1, &dwWritten))
				 {
					 DBG("删除断点失败");
					 return;
				 }
				 i = g_vecCoverData.erase(i);
			 }
			 else
			 {
				 i++;
			 }
		 }
	 }
	 //删除某个断点
	 else if (g_vecInputString.size() == 2)
	 {
		 DWORD nIndex = -1;
		 sscanf(g_vecInputString[1].c_str(), "%d", &nIndex);
		 if (nIndex >= g_vecCoverData.size() || nIndex < 0)
		 {
			 printf("找不到这个断点\n");
			 return;
		 }
		 //
		 if (!WriteProcessMemory(g_hProcess, g_vecCoverData[nIndex].originAddr, &g_vecCoverData[nIndex].data, 1, &dwWritten))
		 {
			 DBG("删除断点失败");
			 return;
		 }
		 if (inVecStepoverBp((DWORD)g_vecCoverData[nIndex].originAddr, nPos))
		 {
			 g_vecBreakPointByStepOver.erase(g_vecBreakPointByStepOver.begin()+nPos);
		 }
		 g_vecCoverData.erase(g_vecCoverData.begin() + nIndex);

	 }
 }
 bool inVecStepoverBp(DWORD addr, int& pos)
 {
	 int nIndex = 0;
	 for (auto i : g_vecBreakPointByStepOver)
	 {
		 if (addr == i)
		 {
			 pos = nIndex;
			 return true;
		 }
		 nIndex++;
	 }
	 return false;
 }
 void clearProtect()
 {
	 LPVOID lpBuff = VirtualAllocEx(g_hProcess, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	 if (!lpBuff)
	 {
		 DBG("隐藏PEB失败");
		 return;
	 }
	 char szPath[] = "D:\\MyCode\\ClassTest\\Debug\\classDll.dll";
	 DWORD beWritten = 0;
	 if (!WriteProcessMemory(g_hProcess, lpBuff, szPath, sizeof(szPath), &beWritten))
	 {
		 DBG("隐藏PEB失败");
		 return;
	 }
	 HANDLE hRemoteThr = CreateRemoteThread(g_hProcess, 0, 0, LPTHREAD_START_ROUTINE(LoadLibraryA), lpBuff, 0, 0);
	 if (!hRemoteThr)
	 {
		 DBG("隐藏PEB失败");
		 CloseHandle(hRemoteThr);
		 return;
	 }
 }
 void setApiBp()
 {
	 printf("API符号>>");
	 char szApiName[32]{};
	 gets_s(szApiName, 32);
	 char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)]{};
	 PSYMBOL_INFO pi = PSYMBOL_INFO(buffer);
	 pi->SizeOfStruct = sizeof(SYMBOL_INFO);
	 pi->MaxNameLen = MAX_SYM_NAME;
	 if (!SymFromName(g_symHprocess, szApiName, pi))
	 {
		 DBG("找不到符号");
		 return;
	 }
	 setInt3BreakPoint(LPVOID(pi->Address));
 }
 void showModuleExportTable()
 {
	 char modName[MAX_PATH]{};
	 printf("模块名>>");
	 gets_s(modName, MAX_PATH);
	 printf("1.导出表\t2.导入表\n>>");
	 int nChoice = 0;
	 scanf("%d", &nChoice);
	 LPVOID dllImageBase = NULL;
	 for (auto i : g_vecModuleInfo)
	 {
		 if (strcmp(i.dllName, modName) == 0)
		 {
			 dllImageBase = (LPVOID)i.dllImageBase;
			 break;
		 }
	 }
	 if (!dllImageBase)
	 {
		 DBG("找不到模块");
		 return;
	 }
	 //dllImageBase就是该模块加载基址
	 IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)dllImageBase;
	 if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
	 {
		 DBG("不是有效PE文件");
		 return;
	 }
	 IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)((DWORD)dllImageBase + pDos->e_lfanew);
	 if (nChoice == 1)
		 showExport(dllImageBase, pNt);
	 if (nChoice == 2)
		 showImport(dllImageBase, pNt);
 }
 //显示指定模块导出表
 void showExport(LPVOID pImagebase, IMAGE_NT_HEADERS* pNt)
 {
	 DWORD pExportRva = pNt->OptionalHeader.DataDirectory[0].VirtualAddress;
	 if (pExportRva == 0)
	 {
		 DBG("无导出表");
		 return;
	 }
	 //导出表目录地址
	 IMAGE_EXPORT_DIRECTORY* pExport = (IMAGE_EXPORT_DIRECTORY*)(DWORD(pImagebase) + pExportRva);
	 DWORD* pEnt = (DWORD*)(pExport->AddressOfNames + (DWORD)pImagebase);
	 DWORD* pEat = (DWORD*)(pExport->AddressOfFunctions + (DWORD)pImagebase);
	 WORD* pEot = (WORD*)(pExport->AddressOfNameOrdinals + (DWORD)pImagebase);

	 char* pFuncName = NULL;
	 for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	 {
		 printf("函数名:%s			RVA:%08x\n", (char*)(pEnt[i] + (DWORD)pImagebase), pEat[pEot[i]]);
	 }
 }
 //显示指定模块导入表
 void showImport(LPVOID pImagebase, IMAGE_NT_HEADERS* pNt)
 {
	 DWORD pImportRva = pNt->OptionalHeader.DataDirectory[1].VirtualAddress;
	 if (pImportRva == 0)
	 {
		 DBG("无导入表");
		 return;
	 }
	 //导入表目录首地址
	 IMAGE_IMPORT_DESCRIPTOR* pImport = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)pImagebase + pImportRva);

	 while (pImport->Name)
	 {
		 char*pName = (char*)(pImport->Name + DWORD(pImagebase));
		 printf("名称:[%s]\n", pName);
		 IMAGE_THUNK_DATA* Int = (IMAGE_THUNK_DATA*)(pImport->OriginalFirstThunk + DWORD(pImagebase));
		 while (Int->u1.Function)
		 {

			 if (IMAGE_SNAP_BY_ORDINAL(Int->u1.Ordinal))
			 {
				 printf("\t序号:%x\n", Int->u1.Ordinal & 0xFFFF);
			 }
			 else
			 {
				 IMAGE_IMPORT_BY_NAME* impName = (IMAGE_IMPORT_BY_NAME*)(Int->u1.AddressOfData + DWORD(pImagebase));
				 printf("\t函数名:%s\n", impName->Name);
			 }
			 Int++;
		 }
		 pImport++;
	 }
 }
 DWORD getProcessPid(wchar_t* szName)
 {
	 PROCESSENTRY32 pe{ sizeof(PROCESSENTRY32) };
	 HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	 BOOL b = Process32First(hSnap, &pe);
	 int pId = -1;
	 if (b)
	 {
		 do {
			 if (wcscmp(pe.szExeFile, szName) == 0)
			 {
				 pId = pe.th32ProcessID;
				 return pId;
			 }
		 } while (Process32Next(hSnap, &pe));
	 }
	 return -1;
 }
 void loadPlugin()
 {
	 //1.遍历加载plugin文件夹下所有DLL
	 travelFolder((CStringA)"plugin");
	 //2.找到pl_init导出函数,如果没有则卸载DLL
	 //3.如果有则执行pl_init函数的内容
 }
 void travelFolder(CStringA& root)
 {
	 WIN32_FIND_DATAA wd{};
	 char dllPath[MAX_PATH]{};
	 HANDLE hFile = FindFirstFileA(root + "\\*", &wd);
	 if (!hFile)return;
	 do {
		 if(strcmp(wd.cFileName,".") == 0 || strcmp(wd.cFileName, "..") == 0)
			 continue;
		 else
		 {
			 vector<string> vecRes = split(wd.cFileName, ".");
			 if(strcmp(vecRes[1].c_str(), "dll"))
				 continue;
			 CStringA temp = root + "\\" + wd.cFileName;
			 strcpy(dllPath, temp.GetBuffer());
			 HMODULE hMod = LoadLibraryA(dllPath);
			 if (!hMod)
				 continue;
			 LPVOID neccessaryAddr = GetProcAddress(hMod, "pl_init");
			 if (neccessaryAddr)
			 {
				 _asm call neccessaryAddr;
				 g_plugin_fun = GetProcAddress(hMod, "plugin_fun");
				 g_plugin_fun2 = GetProcAddress(hMod, "plugin_fun2");
			 }
		 }
	 } while (FindNextFileA(hFile, &wd));
 }

 void setConditionBp(DWORD addr)
 {
	 g_vecConditionBp.push_back(addr);
 }
 bool inConditionTab(LPVOID addr)
 {
	 for (auto i : g_vecConditionBp)
	 {
		 if (i == DWORD(addr))
		 {
			 return true;
		 }
	 }
	 return false;
 }
 void clearMemBp()
 {
	 //1.遍历内存断点表,恢复断点所在分页的原始属性
	 DWORD old = 0;
	 for (auto i : g_vecMemBreakPoint)
	 { 
		 VirtualProtectEx(g_hProcess, (LPVOID)i.bpAddr, 1, i.oldPageAttribute, &old);
	 }
	 //2.清空内存断点表
	 g_vecMemBreakPoint.clear();
 }

 void clearHardwareBp()
 {
	 //1.将DR0-DR3和DR7都置0
	 CONTEXT ct{ CONTEXT_ALL };
	 GetThreadContext(g_hThread, &ct);
	 ct.Dr0 = 0;
	 ct.Dr1 = 0;
	 ct.Dr2 = 0;
	 ct.Dr3 = 0;
	 ct.Dr7 = 0;
	 SetThreadContext(g_hThread, &ct);
	 //2.清空硬件断点表
	 g_vecHardwareBreakPoint.clear();
 }
 bool dumpMemInfo(DWORD startAddr, DWORD nSize)
 {
	 //获取寄存器状态
	 CONTEXT ct{ CONTEXT_ALL };
	 DWORD dwRead = 0, dwWritten = 0;
	 if (!GetThreadContext(g_hThread, &ct))return false;
	 //申请一块空间保存T进程内存信息
	 char* szBuff = new char[nSize] {};
	 if (!szBuff)return false;
	 if (!ReadProcessMemory(g_hProcess, (LPVOID)startAddr, szBuff, nSize, &dwRead))return false;
	 //将读取出来的内存写入dmp文件
	 HANDLE hFile = CreateFileA("1.dmp", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	 if (hFile == INVALID_HANDLE_VALUE)return false;
	 if (!WriteFile(hFile, szBuff, nSize, &dwWritten, 0))
	 {
		 CloseHandle(hFile);
		 return false;
	 }
	 CloseHandle(hFile);
	 delete[] szBuff;
	 return true;
 }
 void miniDump(EXCEPTION_POINTERS* pExpPointer, bool isCrash)
 {
	 //手动dump文件
	 if (isCrash == false)
	 {
		 HANDLE hFile = CreateFileA("minidump.dmp", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
		 if (INVALID_HANDLE_VALUE == hFile)return;
		 if (!MiniDumpWriteDump(g_hProcess, GetProcessId(g_hProcess), hFile, MiniDumpNormal, 0, 0, 0))
		 {
			 DBG("miniDump失败");
		 }
		 CloseHandle(hFile);
	 }
	 //程序崩溃时自动dump文件
	 else
	 {
		 HANDLE hFile = CreateFileA("crash.dmp", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
		 if (INVALID_HANDLE_VALUE == hFile)return;
		 MINIDUMP_EXCEPTION_INFORMATION mei{};
		 mei.ClientPointers = FALSE;
		 mei.ThreadId = GetThreadId(g_hThread);
		 mei.ExceptionPointers = pExpPointer;
		 if (!MiniDumpWriteDump(g_hProcess, GetProcessId(g_hProcess), hFile, MiniDumpNormal, &mei, 0, 0))
		 {
			 DBG("miniDump失败");
		 }
		 CloseHandle(hFile);
	 }
 }
 void editDisasmCode()
 {
	 ks_engine *pengine = NULL;
	 if (KS_ERR_OK != ks_open(KS_ARCH_X86, KS_MODE_32, &pengine))
	 {
		 DBG("反汇编引擎初始化失败");
		 return;
	 }

	 unsigned char* opcode = NULL; // 汇编得到的opcode的缓冲区首地址
	 unsigned int nOpcodeSize = 0; // 汇编出来的opcode的字节数
			   
	 char asmCode[MAX_PATH]{};// 汇编指令	  
	 printf("输入汇编指令>>");// 可以使用分号，或者换行符将指令分隔开
	 gets_s(asmCode, MAX_PATH);
	 int nRet = 0; // 保存函数的返回值，用于判断函数是否执行成功
	 size_t stat_count = 0; // 保存成功汇编的指令的条数

	 DWORD addr = 0;
	 sscanf(g_vecInputString[1].c_str(), "%x", &addr);
	 nRet = ks_asm(pengine, /* 汇编引擎句柄，通过ks_open函数得到*/
		 asmCode, /*要转换的汇编指令*/
		 addr, /*汇编指令所在的地址*/
		 &opcode,/*输出的opcode*/
		 &nOpcodeSize,/*输出的opcode的字节数*/
		 &stat_count /*输出成功汇编的指令的条数*/
	 );
	 
	 // 返回值等于-1时反汇编错误
	 if (nRet == -1)
	 {
		 // 输出错误信息
		 // ks_errno 获得错误码
		 // ks_strerror 将错误码转换成字符串，并返回这个字符串
		 printf("错误信息：%s\n", ks_strerror(ks_errno(pengine)));
		 return;
	 }
	 //将得到的opcode写到T进程的内存中
	 DWORD dwWritten = 0;
	 if (!WriteProcessMemory(g_hProcess, (LPVOID)addr, opcode, strlen((char*)opcode), &dwWritten))
	 {
		 DBG("写入内存失败");
	 }

	 //printf("一共转换了%d条指令\n", stat_count);
	 // 打印汇编出来的opcode
	 //printOpcode(opcode, nOpcodeSize);
	 // 释放空间
	 ks_free(opcode);
	 // 关闭句柄
	 ks_close(pengine);

 }
 void runToRet()
 {
	 //1.得到当前代码所在的地址
	 CONTEXT ct{ CONTEXT_ALL };
	 GetThreadContext(g_hThread, &ct);
	 DWORD eip = ct.Eip;
	 //2.根据目前所在的行找到RET指令所在的行
	 DWORD beRead = 0;
	 DISASM da{};
	 ORIGIN_DATA od{};
	 char* opcode = new char[1024]{};
	 if (!ReadProcessMemory(g_hProcess, (LPVOID)eip, opcode, 1024, &beRead))
	 {
		 DBG_EXIT("读取opcode失败");
	 }
	 da.EIP = (UINT)opcode;
	 da.VirtualAddr = eip;
	 da.Archi = 0;
	 while (1)
	 {
		 //得到已被反汇编的指令长度
		 int retLen = Disasm(&da);
		 DWORD firstOpcode = 0;
		 //g_vecInputString = split(da.CompleteInstr, " ");
		 if (da.Instruction.Opcode == 0xC2 || da.Instruction.Opcode == 0xC3 || da.Instruction.Opcode == 0xCA || da.Instruction.Opcode == 0xCB)
		 {
			 //od.data = da.Instruction.Opcode;
			 //od.originAddr = (LPVOID)da.VirtualAddr;
			 //g_vecCoverData.push_back(od);
			 setInt3BreakPoint(LPVOID(da.VirtualAddr));
			 g_vecBreakPointByStepOver.push_back(DWORD(da.VirtualAddr));
			 break;
		 }
		 //为-1表示找不到该指令对应的反汇编代码
		 da.EIP += retLen;
		 da.VirtualAddr += retLen;
		 if (da.EIP - (DWORD)opcode >= 1024)
		 {
			 break;
		 }
	 }
	 delete[] opcode;
	 opcode = NULL;
 }
 void recordScript()
 {
	 g_isRecordingScript = true;
 }
 void recordOver()
 {
	 g_isRecordingScript = false;
	 HANDLE hFile = CreateFileA("script.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	 if (INVALID_HANDLE_VALUE == hFile)
	 {
		 DBG("脚本录制失败");
		 return;
	 }
	 DWORD dwWritten = 0;
	 for (auto i : g_vectorRecord)
	 {
		 WriteFile(hFile, i.operate, 32, &dwWritten, 0);
	 }
	 CloseHandle(hFile);
 }
 void runScript()
 {
	 g_isRunScript = true;
 }
 char* getCommand(HANDLE hFile)
 {
	 char* buff = new char[32]{};
	 DWORD read = 0;
	 ReadFile(hFile, buff, 32, &read, 0);
	 return buff;
 }
 