#include <stdio.h>
#include "�쳣����.h"
//#include <imagehlp.h>
//T���̵Ľ��̾�����߳̾��,��DbgEvent�п��Ի�ȡ
HANDLE g_hProcess = NULL;
HANDLE g_hThread = NULL;
HANDLE g_symHprocess = NULL;
int g_nChoice = 0;

int main()
{
	//1.�������ԻỰ
	printf("1.����.\n2.����\n>>");
	scanf("%d", &g_nChoice);
	getchar();
	//printf("�����뱻���Գ���·��>>");
	//char path[MAX_PATH]{};
	//gets_s(path, MAX_PATH);
	STARTUPINFOA si{ sizeof(si) };
	PROCESS_INFORMATION pi{};
	if (g_nChoice == 1)
	{
		printf("�����뱻���Գ���·��>>");
		char path[MAX_PATH]{};
		gets_s(path, MAX_PATH);
		if (!CreateProcessA(path, 0, 0, 0, 0, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE, 0, 0, &si, &pi))
		{
			printf("ʧ��!\n");
			return 0;
		}
	}
	if (g_nChoice == 2)
	{
		wchar_t* name = L"class.exe";
		DWORD pId = getProcessPid(name);
		if (!DebugActiveProcess(pId))
		{
			DBG_EXIT("����ʧ��");
		}
	}
	
	//2.���յ�����Ϣ
	DWORD dwRet = DBG_CONTINUE;
	DEBUG_EVENT dbgEvent{};

	while (1)
	{
		//��������˵����¼�,�¼���Ϣ������dbgEvent��
		WaitForDebugEvent(&dbgEvent, -1);
		//��ȡT���̵Ľ��̾�����߳̾��
		g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbgEvent.dwProcessId);
		if (INVALID_HANDLE_VALUE == g_hProcess)
		{
			DBG_EXIT("��ȡT���̾��ʧ��!");
		}
		g_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
		if (INVALID_HANDLE_VALUE == g_hThread)
		{
			DBG_EXIT("��ȡT�����߳̾��ʧ��!");
		}
		switch (dbgEvent.dwDebugEventCode)
		{
			
			case CREATE_PROCESS_DEBUG_EVENT:
			{
				onLoadExeSymbol(&dbgEvent.u.CreateProcessInfo);
				int ii = 0;//������ 
			}
			break;
			case CREATE_THREAD_DEBUG_EVENT :break;
			//�����Խ��̷����쳣,��������Ҫ����������
			case EXCEPTION_DEBUG_EVENT	   :
				dwRet = handleException(&dbgEvent.u.Exception.ExceptionRecord);
				break;
			case EXIT_PROCESS_DEBUG_EVENT  :break;
			case EXIT_THREAD_DEBUG_EVENT   :break;
			case LOAD_DLL_DEBUG_EVENT	   :
			{
				//����DLL����
				onLoadDllSymbol(&dbgEvent.u.LoadDll);
			}
				break;
			case OUTPUT_DEBUG_STRING_EVENT :break;
			case RIP_EVENT				   :break;
			case UNLOAD_DLL_DEBUG_EVENT	   :break;
		}
		//3.�ظ�������ϵͳ:DBG_CONTINUE,�쳣�Ѵ���,DBG_EXCEPTION_NOT_HANDLED:δ����
		if (dwRet == DBG_EXCEPTION_NOT_HANDLED)
		{
			//����ǵ����������˵��쳣,���ܱ����Գ�������,Ȼ��dump�����Ϣ
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