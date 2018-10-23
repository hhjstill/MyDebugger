#include <stdio.h>
#include "异常处理.h"
//#include <imagehlp.h>
//T进程的进程句柄和线程句柄,在DbgEvent中可以获取
HANDLE g_hProcess = NULL;
HANDLE g_hThread = NULL;
HANDLE g_symHprocess = NULL;
int g_nChoice = 0;

int main()
{
	//1.创建调试会话
	printf("1.创建.\n2.附加\n>>");
	scanf("%d", &g_nChoice);
	getchar();
	//printf("请输入被调试程序路径>>");
	//char path[MAX_PATH]{};
	//gets_s(path, MAX_PATH);
	STARTUPINFOA si{ sizeof(si) };
	PROCESS_INFORMATION pi{};
	if (g_nChoice == 1)
	{
		printf("请输入被调试程序路径>>");
		char path[MAX_PATH]{};
		gets_s(path, MAX_PATH);
		if (!CreateProcessA(path, 0, 0, 0, 0, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, 0, 0, &si, &pi))
		{
			printf("失败!\n");
			return 0;
		}
	}
	if (g_nChoice == 2)
	{
		wchar_t* name = L"class.exe";
		DWORD pId = getProcessPid(name);
		if (!DebugActiveProcess(pId))
		{
			DBG_EXIT("附加失败");
		}
	}
	
	//2.接收调试信息
	DWORD dwRet = DBG_CONTINUE;
	DEBUG_EVENT dbgEvent{};

	while (1)
	{
		//如果产生了调试事件,事件信息保存在dbgEvent中
		WaitForDebugEvent(&dbgEvent, -1);
		//获取T进程的进程句柄和线程句柄
		g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbgEvent.dwProcessId);
		if (INVALID_HANDLE_VALUE == g_hProcess)
		{
			DBG_EXIT("获取T进程句柄失败!");
		}
		g_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
		if (INVALID_HANDLE_VALUE == g_hThread)
		{
			DBG_EXIT("获取T进程线程句柄失败!");
		}
		switch (dbgEvent.dwDebugEventCode)
		{
			
			case CREATE_PROCESS_DEBUG_EVENT:
			{
				onLoadExeSymbol(&dbgEvent.u.CreateProcessInfo);
				int ii = 0;//调试用 
			}
			break;
			case CREATE_THREAD_DEBUG_EVENT :break;
			//被调试进程发生异常,调试器主要处理的是这个
			case EXCEPTION_DEBUG_EVENT	   :
				dwRet = handleException(&dbgEvent.u.Exception.ExceptionRecord);
				break;
			case EXIT_PROCESS_DEBUG_EVENT  :break;
			case EXIT_THREAD_DEBUG_EVENT   :break;
			case LOAD_DLL_DEBUG_EVENT	   :
			{
				//加载DLL符号
				onLoadDllSymbol(&dbgEvent.u.LoadDll);
			}
				break;
			case OUTPUT_DEBUG_STRING_EVENT :break;
			case RIP_EVENT				   :break;
			case UNLOAD_DLL_DEBUG_EVENT	   :break;
		}
		//3.回复调试子系统:DBG_CONTINUE,异常已处理,DBG_EXCEPTION_NOT_HANDLED:未处理
		if (dwRet == DBG_EXCEPTION_NOT_HANDLED)
		{
			//如果是调试器处理不了的异常,可能被调试程序会崩溃,然后dump相关信息
			EXCEPTION_POINTERS ep{};
			CONTEXT ct{ CONTEXT_ALL };
			GetThreadContext(g_hThread, &ct);
			ep.ExceptionRecord = &dbgEvent.u.Exception.ExceptionRecord;
			ep.ContextRecord = &ct;
			miniDump(&ep, true);
		}
		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, dwRet);
	}
	return 0;
}