#include "�쳣����.h"
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
//keystoneͷ�ļ��;�̬���ļ�
#include "keystone/keystone.h"
#pragma comment (lib,"keystone/x86/keystone_x86.lib")

//һЩȫ�ֱ���
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
	//�ڴ����쳣��ʱ��,�Ȳ������߶�ʮһ

	if (g_isSetByDbg)
	{
		//1.���������int3�ϵ�ĵ�ַȫ�����ó�CC,���˵�����������callָ���
		renewAllInt3Bp();
		//2.��Ӳ���ϵ�ȫ�����µ��Ĵ���
		renewAllHardBp();
		//3.�����ڴ�ϵ�
		renewAllMemBp();
	}
	DWORD dwRet = DBG_CONTINUE;
	CONTEXT ct{ CONTEXT_CONTROL };
	switch (pExceptionRecord->ExceptionCode)
	{
	//�쳣�����Ƕϵ��쳣:int 3
	case EXCEPTION_BREAKPOINT:
	{
		//ÿ�����̶���һ���̶���ϵͳ�ϵ�
		static bool isSystemBreakpoint = true;
		if (isSystemBreakpoint) {
			isSystemBreakpoint = false;
			//��main�����¶ϵ�
			bpAtEntryPoint();
			//���ز��
			loadPlugin();
		}
		//�������ϵͳ�ϵ�,�ͻָ�֮ǰ��CC���ǵ�����
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
	//�쳣�����Ƿ���Ȩ���쳣
	case EXCEPTION_ACCESS_VIOLATION:
		//������ǵ����������������쳣,��������
		if (!handleMemExption(pExceptionRecord))
			dwRet = DBG_EXCEPTION_NOT_HANDLED;//�������˵㶫��,�������������true
		if (g_hitTargetBp == false)
			goto EXIT;
		break;
	//�쳣������Ӳ���ϵ����TF��־λΪ1
	case EXCEPTION_SINGLE_STEP:
	{
		DWORD dwIndex = -1;
		if (g_isSetByDbg)
		{
			g_isSetByDbg = false;
			goto EXIT;
		}

		//�ж��Ƿ���Ӳ���ϵ�(�������������)
		if ((dwIndex = isHardwareBP()) != -1)
		{
			//��Ӳ���ϵ�,�ں����д���
			//1.ִ�жϵ�  2.���ʶϵ�   3.д�ϵ�
			handleHard_Bp(dwIndex);
		}
	}
		break;
	//����������������쳣
	default:
		dwRet = DBG_EXCEPTION_NOT_HANDLED;
		break;
	}
	//�쳣�������
	//��ʾ�����Ϣ,�練������
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("��ȡ�߳�������ʧ��");
	}
	printDisasm(ct.Eip);

	//��Ȼ�쳣�������,���ڵ�ǰ������û�з����쳣������
	//����T�����Ǵ����ж�״̬
	//��ô���ǵȴ������û�����
	userInput(pExceptionRecord->ExceptionAddress);
EXIT:
	//Ĭ�Ϸ��ص������Ѵ����쳣,�쳣�ַ�����
	return dwRet;
}

void clearInt3BreakPoint(LPVOID pExceptionAddr)
{
	//�ҵ����޸�λ�õ�ԭʼ����,���滻CC
	int nIndex = 0;
	for (auto c: g_vecCoverData)
	{
		DWORD dwWritten = 0;
		if (c.originAddr == pExceptionAddr)
		{
			if (!WriteProcessMemory(g_hProcess, pExceptionAddr, &c.data, 1, &dwWritten))
			{
				DBG_EXIT("�ָ��ϵ�ʧ��!");
			}
			break;
		}
		nIndex++;
	}
	//�жϴ˶ϵ��Ƿ���һ���Զϵ�,�����������ű���ɾ������ϵ�
	int nPos = 0;
	if (inVecStepoverBp((DWORD)pExceptionAddr, nPos))
	{
		g_vecBreakPointByStepOver.erase(g_vecBreakPointByStepOver.begin() + nPos);
		g_vecCoverData.erase(g_vecCoverData.begin() + nIndex);
	}

	//�޸�T���̶ϵ������̵߳�EIP��ֵ,ʹ��ָ��ϵ�λ��
	//����EIPָ��ϵ����һ��ָ��
	//CONTEXT_CONTROL==>���벻ͬ��flagӰ��ct�õ��ļĴ���������
	CONTEXT ct{ CONTEXT_ALL };
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("��ȡ�߳�������ʧ��");
	}
	ct.Eip--;
	if (!SetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("�����߳�������ʧ��");
	}
	//�ж��Ƿ��������ϵ�,���Ƿ���������
	if (inConditionTab(pExceptionAddr))
	{
		if (ct.Eax)
			g_isConditionBp = true;
		else
			g_isConditionBp = false;
	}
	else
		g_isConditionBp = false;
	//����֮ͨ���޸�TF��־λ����һ��������ʱ�ϵ�
	//�Ա������������ʱ�ϵ��ʱ�����½�CC����֮ǰλ�õ�����
	//����֮ǰ�Ķϵ�Ϊһ���Զϵ�
	setSingleStepBreakpoint();
	g_isSetByDbg = true;

}

void setSingleStepBreakpoint()
{
	CONTEXT ct{ CONTEXT_ALL };
	//��ȡ�߳�������
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("��ȡ�߳�������ʧ��");
	}
	//��TF��־λ��1
	EFLAGS* pEflags = (EFLAGS*)&ct.EFlags;
	pEflags->TF = 1;
	//�ٰ��߳����������û�ȥ
	if (!SetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("�����߳�������ʧ��");
	}
}

void setInt3BreakPoint(LPVOID pointAddr)
{
	//���ȶ�ȡ��λ�õ�����
	ORIGIN_DATA od{};
	od.originAddr = pointAddr;
	DWORD beRead = 0, beWritten = 0;
	BYTE int3 = 0xCC;
	if (!ReadProcessMemory(g_hProcess, pointAddr, &od.data, 1, &beRead))DBG("�¶ϵ�ʧ��");
	//����λ�����ݸ�ΪCC
	if(!WriteProcessMemory(g_hProcess, pointAddr, &int3, 1, &beWritten))DBG("�¶ϵ�ʧ��");
	//�����λ�õ�����
	g_vecCoverData.push_back(od);
}

void printDisasm(DWORD eip, int nLen)
{
	DISASM da{};
	DWORD beRead = 0;
	char* opcode = new char[nLen * 15]{};
	if (!ReadProcessMemory(g_hProcess, (LPVOID)eip, opcode, nLen * 15, &beRead))
	{
		DBG_EXIT("��ȡopcodeʧ��");
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
		//�õ��ѱ�������ָ���
		int retLen = Disasm(&da);
		//Ϊ-1��ʾ�Ҳ�����ָ���Ӧ�ķ�������
		if (retLen == -1)break;
		//�����������
		printf("%I64X | %s",
			da.VirtualAddr, da.CompleteInstr);
		//���Դ���=================================================================================
		//�ֽ���ָ��
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
					DBG("��ȡ�ڴ�ʧ��");
				}
				if (GetSymName(g_symHprocess, (SIZE_T)realAddr, strName))
				{
					printf(" ==> %S", strName.GetBuffer());
				}
			}
		}
		printf("\n");
		//���Դ���=================================================================================
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
		DBG_EXIT("��ȡT�����ڴ�ʧ��");
	}
	char* opcode = new char[15]{};
	if (!ReadProcessMemory(g_hProcess, (LPVOID)curCommandAddr, opcode, 15, &beRead))
	{
		DBG_EXIT("��ȡopcodeʧ��");
	}
	da.EIP = (UINT)opcode;
	da.VirtualAddr = curCommandAddr;
#ifdef _WIN32
	da.Archi = 0;
#else
	da.Archi = 64;
#endif // _WIN32

	//�õ��ѱ�������ָ���
	int retLen = Disasm(&da);
	//Ϊ-1��ʾ�Ҳ�����ָ���Ӧ�ķ�������
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
	//1.�ж�DR0-DR3���Ƿ��п��мĴ���
	CONTEXT ct{ CONTEXT_ALL };
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("��ȡ�߳�������ʧ��");
	}
	int nNum = whoIsFree();
	if (nNum == -1)
	{
		printf("�¶�ʧ��,���޿��мĴ���..\n");
		return;
	}
	//2.�޸�DR7�Ĵ�����Ӧ�ֶε�ֵ
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	//inter�Ƽ���LE��GE�������ֶ���λ
	pDr7->LE = 1;
	pDr7->GE = 1;
	switch (nNum)
	{
	//DR0�п�
	case 0:
		if (nType == 0 || nByteLen == 0)
			ct.Dr0 = addr;
		else
		{
			//���ֽڶϵ�
			if(nByteLen == 1)
				ct.Dr0 = addr - addr % 2;
			//���ֽڶϵ�
			else
				ct.Dr0 = addr - addr % 4;
		}
			
		pDr7->L0 = 1;
		pDr7->RW0 = nType;
		pDr7->LEN0 = nByteLen;
		break;
	//DR1�п�
	case 1:
		if (nType == 0 || nByteLen == 0)
			ct.Dr1 = addr;
		else
		{
			//���ֽڶϵ�
			if (nByteLen == 1)
				ct.Dr1 = addr - addr % 2;
			//���ֽڶϵ�
			else
				ct.Dr1 = addr - addr % 4;
		}
		pDr7->L1 = 1;
		pDr7->RW1 = nType;
		pDr7->LEN1 = nByteLen;
		break;
	//DR2�п�
	case 2:
		if (nType == 0 || nByteLen == 0)
			ct.Dr2 = addr;
		else
		{
			//���ֽڶϵ�
			if (nByteLen == 1)
				ct.Dr2 = addr - addr % 2;
			//���ֽڶϵ�
			else
				ct.Dr2 = addr - addr % 4;
		}
		pDr7->L2 = 1;
		pDr7->RW2 = nType;
		pDr7->LEN2 = nByteLen;
		break;
	//DR3�п�
	case 3:
		if (nType == 0 || nByteLen == 0)
			ct.Dr3 = addr;
		else
		{
			//���ֽڶϵ�
			if (nByteLen == 1)
				ct.Dr3 = addr - addr % 2;
			//���ֽڶϵ�
			else
				ct.Dr3 = addr - addr % 4;
		}
		pDr7->L3 = 1;
		pDr7->RW3 = nType;
		pDr7->LEN3 = nByteLen;
		break;
	default:
		//printf("�¶�ʧ��,���޿��мĴ���..\n");
		return;
	}
	
	//3.�����������û�ȥ
	if (!SetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("�����߳�������ʧ��");
	}
	//4.����ϵ��¼
	HARD_BP hb{};
	hb.bpAddr = (LPVOID)addr;
	hb.reg = nNum;
	hb.type = nType;
	g_vecHardwareBreakPoint.push_back(hb);
}
int whoIsFree()
{
	//��ȡDR0-DR3��ֵ
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
		DBG_EXIT("��ȡ�߳�������ʧ��");
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
//		//��Ҫ�ж�Ӳ���ϵ���е�����
//		//1.�����ִ�жϵ�,ֱ����pExpRcd�е��쳣��ַ��i.addr�ȽϾ�����
//		//2.����Ƕ�д�ϵ�,����Ҫ��pExcRcd�е�information[1]��i.addr�Ƚ�
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
		DBG_EXIT("��ȡ�߳�������ʧ��");
	}
	//�õ���ǰӲ���ϵ�ṹ����Ϣ
	HARD_BP curStcBpInfo = g_vecHardwareBreakPoint[nIndex];
	//1.�ж��Ǻ������͵�Ӳ���ϵ�,д,��д,����ִ��
	switch (curStcBpInfo.type)
	{
	//2.�޸���Ӧ�ļĴ�����ֵ
	case 0:		//ִ�жϵ�
	{
		//��ǰEIP��λ��ָ��ϵ�λ��,�����Ҫ���öϵ���ʱ���,��Ȼ�����޷�����ִ��
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
	case 1:		//д�ϵ�,����д�ϵ�ͷ��ʶϵ�:����ָ���ѱ�ִ��,eipָ��ϵ���һ��ָ��
	case 3:		//���ʶϵ�,����д�ϵ�ͷ��ʶϵ�:����ָ���ѱ�ִ��,eipָ��ϵ���һ��ָ��
		//���߲���һ��,������֮����ʾ�����������ʾ����EIP��λ��,�ϵ�λ�õķ����������ʾ��������
		break;
	default:
		break;
	}
	//3.�����������û�ȥ
	if (!SetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("�����߳�������ʧ��");
	}
	//4.���õ���TF�ϵ�,�Ա�ִ��һ��֮��ָ�Ӳ���ϵ�Ĵ�����ֵ
	setSingleStepBreakpoint();
	g_isSetByDbg = true;
}
void renewAllHardBp()
{
	CONTEXT ct{ CONTEXT_ALL };
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("��ȡ�߳�������ʧ��");
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
		DBG_EXIT("�����߳�������ʧ��");
	}
}
void showCurReg()
{
	CONTEXT ct{ CONTEXT_ALL };
	//SuspendThread(g_hThread);
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG_EXIT("��ȡ�߳�������ʧ��");
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
	//��CC���¸��Ƕϵ�λ������
	DWORD dwWritten = 0;
	for (auto c : g_vecCoverData)
	{
		if (!WriteProcessMemory(g_hProcess, c.originAddr, "\xCC", 1, &dwWritten))
		{
			DBG_EXIT("�ָ��ϵ�ʧ��");
		}
	}
}
void userInput(LPVOID pExpAddr)
{
	while (1)
	{
		printf("����>>");
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
				printf("\n--------------------------\n�ű��������\n--------------------------\n");
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
		//�����"g"����,����ֱ�Ӹ�T���̷���(VS��F5)
		if (_stricmp(szCmd, "g") == 0)
		{
			break;
		}
		//�����"t"����,��ʾ��������(VS��F11)
		else if (_stricmp(szCmd, "t") == 0)
		{
			//����һ�������ϵ�
			setSingleStepBreakpoint();
			g_isSetByDbg = false;
			break;
		}
		//�����"p"����,��ʾ��������(VS��F10)
		else if (_stricmp(szCmd, "p") == 0)
		{

			//�����ǰָ����callָ��,������һ��ָ��λ����һ��int 3�ϵ�
			//���򵱳�"t"�����
			//��һ���ϵ���һ���Ե�,��˲���Ҫ�ڲ����󱻻ָ�
			//��ȡ��һ��ָ��ĵ�ַ
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
		//�����"ret"����, ���е�����
		else if (_stricmp(szCmd, "ret") == 0)
		{
			runToRet();
			break;
		}
		//�����"bp"����,��ʾ��ĳ�����öϵ�
		else if (_stricmp(szCmd, "bp") == 0)
		{
			//�ٽ���һ����Ҫ�¶ϵ�ĵ�ַ
			printf("�¶ϵ�ַ>>");
			DWORD pointAddr = 0;
			scanf_s("%x", &pointAddr);
			setInt3BreakPoint((LPVOID)pointAddr);
			while (getchar() != '\n');
		}
		else if (_stricmp(szCmd, "bl") == 0)
		{
			//��ѯ���жϵ�
			int nIndex = 1;
			for (auto c : g_vecCoverData)
			{
				printf("%d  ==>  %08X\n", nIndex, (DWORD)c.originAddr);
				nIndex++;
			}

		}
		//�����"he"����,��ʾ��Ӳ��ִ�жϵ�
		else if (_stricmp(szCmd, "he") == 0)
		{
			//�ٽ���һ����Ҫ�¶ϵ�ĵ�ַ
			printf("�¶ϵ�ַ>>");
			DWORD pointAddr = 0;
			scanf_s("%x", &pointAddr);
			//����һ��ִ�жϵ�
			setHardwareBreakPoint(pointAddr);
			while (getchar() != '\n');
		}
		//�����"hw"����,��ʾ��Ӳ��д�ϵ�
		else if (_stricmp(szCmd, "hw") == 0)
		{
			//�ٽ���һ����Ҫ�¶ϵ�ĵ�ַ
			printf("�¶ϵ�ַ & ���ݳ�������(0,1,3)>>");
			DWORD pointAddr = 0, nLen = 0;
			scanf_s("%x %d", &pointAddr, &nLen);
			if (nLen != 0 && nLen != 1 && nLen != 3)
				printf("�����ܶϵ����ݳ���: %d\n", nLen);
			//����һ��Ӳ��д�ϵ�
			else
				setHardwareBreakPoint(pointAddr, 1, nLen);
			while (getchar() != '\n');
		}//����
		//�����"mr"����,��ʾ���ڴ���ʶϵ�
		else if (_stricmp(szCmd, "mr") == 0)
		{
			//�ٽ���һ����Ҫ�¶ϵ�ĵ�ַ
			printf("�¶ϵ�ַ>>");
			DWORD pointAddr = 0;
			scanf_s("%x", &pointAddr);

			//����һ���ڴ���ʶϵ�
			setMemBreakPoint(pointAddr);
			while (getchar() != '\n');
		}
		//Ӳ�����ʶϵ�
		else if (_stricmp(szCmd, "hr") == 0)
		{
			//�ٽ���һ����Ҫ�¶ϵ�ĵ�ַ
			printf("�¶ϵ�ַ & ���ݳ�������(0,1,3)>>");
			DWORD pointAddr = 0, nLen = 0;
			scanf_s("%x %d", &pointAddr, &nLen);
			if (nLen != 0 && nLen != 1 && nLen != 3)
				printf("�����ܶϵ����ݳ���: %d\n", nLen);
			//����һ��Ӳ�����ʶϵ�
			else
				setHardwareBreakPoint(pointAddr, 3, nLen);
			while (getchar() != '\n');
		}
		//�鿴T���̼Ĵ���
		else if (_stricmp(szCmd, "r") == 0)
		{
			showCurReg();
		}
		//�鿴�ڴ�
		else if (_stricmp(szCmd, "dd") == 0)
		{
			//�ٽ���һ����Ҫ���ڴ�ĵ�ַ
			printf("��ַ>>");
			DWORD memAddr = 0;
			scanf_s("%x", &memAddr);
			while (getchar() != '\n');
			showMem(memAddr);
		}
		else if (_stricmp(g_vecInputString[0].c_str(), "dd") == 0 && g_vecInputString.size() == 2)
		{
			showMem2();
		}
		//�鿴ջ
		else if (_stricmp(szCmd, "ds") == 0)
		{
			showStack();
		}
		//�޸ļĴ���
		else if (_stricmp(g_vecInputString[0].c_str(), "r") == 0 && g_vecInputString.size() == 3)
		{
			editReg();
		}
		//�޸��ڴ�����
		else if (_stricmp(g_vecInputString[0].c_str(), "m") == 0 && g_vecInputString.size() == 3)
		{
			editMem();
		}
		//�鿴������
		else if (_stricmp(g_vecInputString[0].c_str(), "u") == 0 && g_vecInputString.size() == 2)
		{
			CONTEXT ct{ CONTEXT_ALL };
			if (!GetThreadContext(g_hThread, &ct))
			{
				DBG_EXIT("��ȡ�̻߳���ʧ��");
			}
			DWORD eip = ct.Eip;
			int nLen = 0;
			sscanf(g_vecInputString[1].c_str(), "%d", &nLen);
			printDisasm(eip, nLen);
		}
		//�鿴ָ����ַ�Ļ�����
		else if (_stricmp(g_vecInputString[0].c_str(), "ua") == 0 && g_vecInputString.size() == 2)
		{
			DWORD addr = 0;
			sscanf(g_vecInputString[1].c_str(), "%x", &addr);
			printDisasm(addr);
		}
		//�޸ķ�������
		else if (_stricmp(g_vecInputString[0].c_str(), "ue") == 0 && g_vecInputString.size() == 2)
		{
			editDisasmCode();
		}
		//��ʾģ����Ϣ
		else if (_stricmp(szCmd, "mod") == 0)
		{
			showModule();
		}
		//��ʾԴ����
		else if (_stricmp(szCmd, "l") == 0)
		{
			cppDebug();
		}
		//���int3�ϵ�
		else if (_stricmp(g_vecInputString[0].c_str(), "bc") == 0)
		{
			clearBreakPoint();
		}
		//peb����
		else if (_stricmp(g_vecInputString[0].c_str(), "hide") == 0)
		{
			clearProtect();
		}
		//API�ϵ�
		else if (_stricmp(szCmd, "api") == 0)
		{
			setApiBp();
		}
		//��ʾģ�鵼�뵼����
		else if (_stricmp(szCmd, "tab") == 0)
		{
			showModuleExportTable();
			while (getchar() != '\n');
		}
		//ʹ�ò������
		else if (_stricmp(szCmd, "pf") == 0)
		{
			_asm call g_plugin_fun;
		}
		else if (_stricmp(szCmd, "pf2") == 0)
		{
			_asm call g_plugin_fun2;
		}
		//���������ϵ�
		else if (g_vecInputString.size() == 2 && _stricmp(g_vecInputString[0].c_str(), "bp") == 0)
		{
			setConditionBp((DWORD)pExpAddr);
		}
		//����ڴ�ϵ�
		else if (_stricmp(g_vecInputString[0].c_str(), "bcm") == 0)
		{
			clearMemBp();
		}
		//���Ӳ���ϵ�
		else if (_stricmp(g_vecInputString[0].c_str(), "bch") == 0)
		{
			clearHardwareBp();
		}
		//dumpָ���ڴ�����
		else if (_stricmp(szCmd, "dmp") == 0)
		{
			printf("��ʼ��ַ & ��С>>");
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
		//��ʼ¼�ƽű�
		else if (_stricmp(szCmd, "start") == 0)
		{
			recordScript();
		}
		//����¼�ƽű�
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
			DBG("��Ч��ַ");
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
	//�Ƚ������ҳ�����Ը�Ϊû��Ȩ��
	if (!VirtualProtectEx(g_hProcess,(LPVOID)memBpAddr, 1, PAGE_NOACCESS, &mb.oldPageAttribute))
	{
		DBG("�޸ķ�ҳ����ʧ��");
		return;
	}
	if (mb.oldPageAttribute != PAGE_READWRITE && mb.oldPageAttribute != PAGE_EXECUTE_READWRITE 
		&& mb.oldPageAttribute != PAGE_EXECUTE_WRITECOPY)
	{
		DBG("�÷�ҳ���ڴ�д������");
		//�ָ���ҳ����
		VirtualProtectEx(g_hProcess,(LPVOID)memBpAddr, 1, mb.oldPageAttribute, &mb.oldPageAttribute);
		return;
	}
	//�����¶ϳɹ�,��¼�ڴ�ϵ��������
	g_vecMemBreakPoint.push_back(mb);
}
bool handleMemExption(EXCEPTION_RECORD* pExceptionRecord)
{
	//1.�ж��쳣��ַ��ҳ�Ƿ����û��µ��ڴ���ʶϵ����ڷ�ҳ
	bool isSetByUser = false;
	for (auto i : g_vecMemBreakPoint)
	{
		if (i.pageBaseAddr == (pExceptionRecord->ExceptionInformation[1] - pExceptionRecord->ExceptionInformation[1] % 0x1000))
		{
			isSetByUser = true;			
			DWORD old = 0;
			if (!VirtualProtectEx(g_hProcess, (LPVOID)i.bpAddr, 1, i.oldPageAttribute, &old))
			{
				DBG("�ָ���ҳ����ʧ��");
			}
			setSingleStepBreakpoint();
			g_isSetByDbg = true;
			//2.�жϸõ�ַ�Ƿ��������û��¶ϵ�ĵ�ַ
			//����Ŀ��ϵ�
			if (i.bpAddr != (DWORD)pExceptionRecord->ExceptionInformation[1])//����Ƚϵ����ݴ���,ExceptionAddress����ָ��ĵ�ַ,�����ڴ�Ȩ�޲������ڴ��ַ,�������ExceptionInformation[1]
			{
				g_hitTargetBp = false;
				break;
			}
			//����Ŀ��ϵ�
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
			DBG("�޸ķ�ҳ����ʧ��");
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
		DBG("��ȡ��ջ��Ϣʧ��");
		return;
	}
	//��ȡʮ����Ϣ
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
		DBG("��ȡ�߳�������ʧ��");
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
		DBG("��ȡ�߳�������ʧ��");
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
		DBG("�޸��ڴ�ʧ��");
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
		DBG("��ȡ�ڴ�ʧ��");
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
		DBG_EXIT("ö�ٽ���ģ��ʧ��");
	}
	DWORD dwRealSize = dwNeeded / sizeof(HMODULE);
	for (DWORD i = 0; i < dwRealSize; i++)
	{
		if (!GetModuleInformation(g_hProcess, hMod[i], &mi, sizeof(mi)))
		{
			DBG("��ȡģ����Ϣʧ��");
		}
		GetModuleFileNameExA(g_hProcess, hMod[i], szBuff, MAX_PATH);
		printf("���ػ�ַ:%08X          ģ����:%s\n", (DWORD)mi.lpBaseOfDll, szBuff);
		record.dllImageBase = (DWORD)mi.lpBaseOfDll;
		strcpy(record.dllName, szBuff);
		g_vecModuleInfo.push_back(record);
	}
}
void onLoadExeSymbol(CREATE_PROCESS_DEBUG_INFO *pInfo)
{
	g_symHprocess = g_hProcess;
	if (SymInitialize(g_symHprocess, "D:\\c����\\ClassTest\\Debug\\class.pdb", false))
	{
		DWORD64 moduleAddr = SymLoadModule64(g_hProcess, pInfo->hFile, 0, 0, (DWORD64)pInfo->lpBaseOfImage, 0);
		if (!moduleAddr)
		{
			DBG("���ط��ŵ�����Ϣʧ��");
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
		DBG("���ط��ŵ�����Ϣʧ��");
	}
	CloseHandle(pInfo->hFile);
}
void cppDebug()
{
	CONTEXT ct{ CONTEXT_ALL };
	if (!GetThreadContext(g_hThread, &ct))
	{
		DBG("��ȡ�߳�������ʧ��");
		return;
	}
	DWORD displacement = 0;
	IMAGEHLP_LINE64 pl{};
	pl.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

	//���ݻ������ַ��ȡ�к�,�кű�����pl��LineNumber��
	//�����������,Ȼ������Դ�ļ����ͻ������Ӧ��Դ�������ڵ���.
	
	if (!SymGetLineFromAddr64(g_symHprocess, ct.Eip, &displacement, &pl))
	{
		DBG("��ȡ��Ϣʧ��");
		return;
	}
	//�����кŻ�ȡ�е�ַ
	IMAGEHLP_LINE64 lineAddr{};
	lineAddr.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
	//���ƫ�������жϵ�ǰ���Ƿ�Ϊ��Ч��(��������л�����),Ϊ0����Ч
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
		SymGetLineFromName64(g_symHprocess, 0, "D:\\c����\\ClassTest\\class\\main.cpp", lineNumber, &offset, &lineAddr);
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
	 //ɾ�����жϵ�
	 int nPos = 0;
	 if (g_vecInputString.size() == 1)
	 {
		 //����ͨ��STEPOVER���õ�int3�ϵ�,������ȫ���ָ�ԭʼ���ݲ�ɾ��
		 for (auto i = g_vecCoverData.begin(); i != g_vecCoverData.end();)
		 {
			 //����ͨ��STEPOVER���õ�int3�ϵ�
			 if (!inVecStepoverBp((DWORD)i->originAddr, nPos))
			 {
				 if (!WriteProcessMemory(g_hProcess, i->originAddr, &i->data, 1, &dwWritten))
				 {
					 DBG("ɾ���ϵ�ʧ��");
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
	 //ɾ��ĳ���ϵ�
	 else if (g_vecInputString.size() == 2)
	 {
		 DWORD nIndex = -1;
		 sscanf(g_vecInputString[1].c_str(), "%d", &nIndex);
		 if (nIndex >= g_vecCoverData.size() || nIndex < 0)
		 {
			 printf("�Ҳ�������ϵ�\n");
			 return;
		 }
		 //
		 if (!WriteProcessMemory(g_hProcess, g_vecCoverData[nIndex].originAddr, &g_vecCoverData[nIndex].data, 1, &dwWritten))
		 {
			 DBG("ɾ���ϵ�ʧ��");
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
		 DBG("����PEBʧ��");
		 return;
	 }
	 char szPath[] = "D:\\MyCode\\ClassTest\\Debug\\classDll.dll";
	 DWORD beWritten = 0;
	 if (!WriteProcessMemory(g_hProcess, lpBuff, szPath, sizeof(szPath), &beWritten))
	 {
		 DBG("����PEBʧ��");
		 return;
	 }
	 HANDLE hRemoteThr = CreateRemoteThread(g_hProcess, 0, 0, LPTHREAD_START_ROUTINE(LoadLibraryA), lpBuff, 0, 0);
	 if (!hRemoteThr)
	 {
		 DBG("����PEBʧ��");
		 CloseHandle(hRemoteThr);
		 return;
	 }
 }
 void setApiBp()
 {
	 printf("API����>>");
	 char szApiName[32]{};
	 gets_s(szApiName, 32);
	 char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)]{};
	 PSYMBOL_INFO pi = PSYMBOL_INFO(buffer);
	 pi->SizeOfStruct = sizeof(SYMBOL_INFO);
	 pi->MaxNameLen = MAX_SYM_NAME;
	 if (!SymFromName(g_symHprocess, szApiName, pi))
	 {
		 DBG("�Ҳ�������");
		 return;
	 }
	 setInt3BreakPoint(LPVOID(pi->Address));
 }
 void showModuleExportTable()
 {
	 char modName[MAX_PATH]{};
	 printf("ģ����>>");
	 gets_s(modName, MAX_PATH);
	 printf("1.������\t2.�����\n>>");
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
		 DBG("�Ҳ���ģ��");
		 return;
	 }
	 //dllImageBase���Ǹ�ģ����ػ�ַ
	 IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)dllImageBase;
	 if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
	 {
		 DBG("������ЧPE�ļ�");
		 return;
	 }
	 IMAGE_NT_HEADERS* pNt = (IMAGE_NT_HEADERS*)((DWORD)dllImageBase + pDos->e_lfanew);
	 if (nChoice == 1)
		 showExport(dllImageBase, pNt);
	 if (nChoice == 2)
		 showImport(dllImageBase, pNt);
 }
 //��ʾָ��ģ�鵼����
 void showExport(LPVOID pImagebase, IMAGE_NT_HEADERS* pNt)
 {
	 DWORD pExportRva = pNt->OptionalHeader.DataDirectory[0].VirtualAddress;
	 if (pExportRva == 0)
	 {
		 DBG("�޵�����");
		 return;
	 }
	 //������Ŀ¼��ַ
	 IMAGE_EXPORT_DIRECTORY* pExport = (IMAGE_EXPORT_DIRECTORY*)(DWORD(pImagebase) + pExportRva);
	 DWORD* pEnt = (DWORD*)(pExport->AddressOfNames + (DWORD)pImagebase);
	 DWORD* pEat = (DWORD*)(pExport->AddressOfFunctions + (DWORD)pImagebase);
	 WORD* pEot = (WORD*)(pExport->AddressOfNameOrdinals + (DWORD)pImagebase);

	 char* pFuncName = NULL;
	 for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	 {
		 printf("������:%s			RVA:%08x\n", (char*)(pEnt[i] + (DWORD)pImagebase), pEat[pEot[i]]);
	 }
 }
 //��ʾָ��ģ�鵼���
 void showImport(LPVOID pImagebase, IMAGE_NT_HEADERS* pNt)
 {
	 DWORD pImportRva = pNt->OptionalHeader.DataDirectory[1].VirtualAddress;
	 if (pImportRva == 0)
	 {
		 DBG("�޵����");
		 return;
	 }
	 //�����Ŀ¼�׵�ַ
	 IMAGE_IMPORT_DESCRIPTOR* pImport = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)pImagebase + pImportRva);

	 while (pImport->Name)
	 {
		 char*pName = (char*)(pImport->Name + DWORD(pImagebase));
		 printf("����:[%s]\n", pName);
		 IMAGE_THUNK_DATA* Int = (IMAGE_THUNK_DATA*)(pImport->OriginalFirstThunk + DWORD(pImagebase));
		 while (Int->u1.Function)
		 {

			 if (IMAGE_SNAP_BY_ORDINAL(Int->u1.Ordinal))
			 {
				 printf("\t���:%x\n", Int->u1.Ordinal & 0xFFFF);
			 }
			 else
			 {
				 IMAGE_IMPORT_BY_NAME* impName = (IMAGE_IMPORT_BY_NAME*)(Int->u1.AddressOfData + DWORD(pImagebase));
				 printf("\t������:%s\n", impName->Name);
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
	 //1.��������plugin�ļ���������DLL
	 travelFolder((CStringA)"plugin");
	 //2.�ҵ�pl_init��������,���û����ж��DLL
	 //3.�������ִ��pl_init����������
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
	 //1.�����ڴ�ϵ��,�ָ��ϵ����ڷ�ҳ��ԭʼ����
	 DWORD old = 0;
	 for (auto i : g_vecMemBreakPoint)
	 { 
		 VirtualProtectEx(g_hProcess, (LPVOID)i.bpAddr, 1, i.oldPageAttribute, &old);
	 }
	 //2.����ڴ�ϵ��
	 g_vecMemBreakPoint.clear();
 }

 void clearHardwareBp()
 {
	 //1.��DR0-DR3��DR7����0
	 CONTEXT ct{ CONTEXT_ALL };
	 GetThreadContext(g_hThread, &ct);
	 ct.Dr0 = 0;
	 ct.Dr1 = 0;
	 ct.Dr2 = 0;
	 ct.Dr3 = 0;
	 ct.Dr7 = 0;
	 SetThreadContext(g_hThread, &ct);
	 //2.���Ӳ���ϵ��
	 g_vecHardwareBreakPoint.clear();
 }
 bool dumpMemInfo(DWORD startAddr, DWORD nSize)
 {
	 //��ȡ�Ĵ���״̬
	 CONTEXT ct{ CONTEXT_ALL };
	 DWORD dwRead = 0, dwWritten = 0;
	 if (!GetThreadContext(g_hThread, &ct))return false;
	 //����һ��ռ䱣��T�����ڴ���Ϣ
	 char* szBuff = new char[nSize] {};
	 if (!szBuff)return false;
	 if (!ReadProcessMemory(g_hProcess, (LPVOID)startAddr, szBuff, nSize, &dwRead))return false;
	 //����ȡ�������ڴ�д��dmp�ļ�
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
	 //�ֶ�dump�ļ�
	 if (isCrash == false)
	 {
		 HANDLE hFile = CreateFileA("minidump.dmp", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
		 if (INVALID_HANDLE_VALUE == hFile)return;
		 if (!MiniDumpWriteDump(g_hProcess, GetProcessId(g_hProcess), hFile, MiniDumpNormal, 0, 0, 0))
		 {
			 DBG("miniDumpʧ��");
		 }
		 CloseHandle(hFile);
	 }
	 //�������ʱ�Զ�dump�ļ�
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
			 DBG("miniDumpʧ��");
		 }
		 CloseHandle(hFile);
	 }
 }
 void editDisasmCode()
 {
	 ks_engine *pengine = NULL;
	 if (KS_ERR_OK != ks_open(KS_ARCH_X86, KS_MODE_32, &pengine))
	 {
		 DBG("����������ʼ��ʧ��");
		 return;
	 }

	 unsigned char* opcode = NULL; // ���õ���opcode�Ļ������׵�ַ
	 unsigned int nOpcodeSize = 0; // ��������opcode���ֽ���
			   
	 char asmCode[MAX_PATH]{};// ���ָ��	  
	 printf("������ָ��>>");// ����ʹ�÷ֺţ����߻��з���ָ��ָ���
	 gets_s(asmCode, MAX_PATH);
	 int nRet = 0; // ���溯���ķ���ֵ�������жϺ����Ƿ�ִ�гɹ�
	 size_t stat_count = 0; // ����ɹ�����ָ�������

	 DWORD addr = 0;
	 sscanf(g_vecInputString[1].c_str(), "%x", &addr);
	 nRet = ks_asm(pengine, /* �����������ͨ��ks_open�����õ�*/
		 asmCode, /*Ҫת���Ļ��ָ��*/
		 addr, /*���ָ�����ڵĵ�ַ*/
		 &opcode,/*�����opcode*/
		 &nOpcodeSize,/*�����opcode���ֽ���*/
		 &stat_count /*����ɹ�����ָ�������*/
	 );
	 
	 // ����ֵ����-1ʱ��������
	 if (nRet == -1)
	 {
		 // ���������Ϣ
		 // ks_errno ��ô�����
		 // ks_strerror ��������ת�����ַ���������������ַ���
		 printf("������Ϣ��%s\n", ks_strerror(ks_errno(pengine)));
		 return;
	 }
	 //���õ���opcodeд��T���̵��ڴ���
	 DWORD dwWritten = 0;
	 if (!WriteProcessMemory(g_hProcess, (LPVOID)addr, opcode, strlen((char*)opcode), &dwWritten))
	 {
		 DBG("д���ڴ�ʧ��");
	 }

	 //printf("һ��ת����%d��ָ��\n", stat_count);
	 // ��ӡ��������opcode
	 //printOpcode(opcode, nOpcodeSize);
	 // �ͷſռ�
	 ks_free(opcode);
	 // �رվ��
	 ks_close(pengine);

 }
 void runToRet()
 {
	 //1.�õ���ǰ�������ڵĵ�ַ
	 CONTEXT ct{ CONTEXT_ALL };
	 GetThreadContext(g_hThread, &ct);
	 DWORD eip = ct.Eip;
	 //2.����Ŀǰ���ڵ����ҵ�RETָ�����ڵ���
	 DWORD beRead = 0;
	 DISASM da{};
	 ORIGIN_DATA od{};
	 char* opcode = new char[1024]{};
	 if (!ReadProcessMemory(g_hProcess, (LPVOID)eip, opcode, 1024, &beRead))
	 {
		 DBG_EXIT("��ȡopcodeʧ��");
	 }
	 da.EIP = (UINT)opcode;
	 da.VirtualAddr = eip;
	 da.Archi = 0;
	 while (1)
	 {
		 //�õ��ѱ�������ָ���
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
		 //Ϊ-1��ʾ�Ҳ�����ָ���Ӧ�ķ�������
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
		 DBG("�ű�¼��ʧ��");
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
 