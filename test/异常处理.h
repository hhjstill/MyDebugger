#pragma once
#include <windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "../Debug/DbgHelp.Lib")
#include <string>
#include <vector>
#include <atlstr.h>
using std::string;
using std::vector;
#ifdef _DEBUG
#define DBG(str) printf("%s %s %d: %s\n",__FILE__,__FUNCTION__,__LINE__,str);
#define DBG_EXIT(str) printf("%s %s %d: %s\n",__FILE__,__FUNCTION__,__LINE__,str); exit(0);
#endif

//��¼��CC���ǵ����ݵĽṹ��
typedef struct _ORIGIN_DATA
{
	LPVOID originAddr;
	BYTE data;
}ORIGIN_DATA;
//��¼Ӳ���ϵ�ṹ��
typedef struct _HARD_BREAKPOINT
{
	LPVOID bpAddr;  //�ϵ�λ��
	int type;		//�ϵ�����,ִ��,д���߶�д
	int reg;		//��DR0-DR3��һ���Ĵ����б���
}HARD_BP;
//��¼�ڴ�ϵ�ṹ��
typedef struct _MEMORY_BREAKPOINT
{
	DWORD pageBaseAddr;		//��ҳ��ʼ��λ��
	DWORD bpAddr;			//�ڴ�ϵ�λ��
	DWORD oldPageAttribute;	//�ɵķ�ҳ����
}MEM_BP;
typedef struct _MODULE_INFO
{
	DWORD dllImageBase;
	char dllName[MAX_PATH];
}MOD_INFO;
typedef struct _SCRIPT_RECORD
{
	char operate[32];
}SCRIPT;
//��������WaitForDebugEvent�յ��˱����Խ����쳣�¼���ʱ����øú��������쳣
DWORD handleException(EXCEPTION_RECORD* pExceptionRecord);
//�ָ���CC���ǵ�һ��λ�õ�����
void clearInt3BreakPoint(LPVOID pExceptionAddr);
//ͨ����TF��־λ��1,ʹ�ó���ֻ��ִ�е�ǰEIPָ�����һ��ָ��
//֮��������EXCEPTION_SINGLE_STEP�쳣
void setSingleStepBreakpoint();
//��ָ��λ����һ��int 3�ϵ�
void setInt3BreakPoint(LPVOID pointAddr);
//���ݴ�������EIP��ʾ��EIP�����Ժ�λ�õĻ�����
//nLen����Ҫ��ʾ�Ļ����������
void printDisasm(DWORD eip, int nLen = 10);
//���ݵ�ǰָ���ַ��ȡ��һ��ָ��ĵ�ַ,�����ص�ǰָ���ǰ�����ֽ�
DWORD getNextCommandAddr(const DWORD& curCommandAddr, DWORD& nextCommandAddr);
//���ݵ�ַ��Ӳ��ִ�жϵ�
void setHardwareBreakPoint(DWORD addr, int nType = 0, int nByteLen = 0);
//�ж�DR0-DR3���ĸ��Ĵ�������,�����ҵ��ĵ�һ�����мĴ���,û���򷵻�-1
int whoIsFree();
//��ȡĳ���Ĵ�����ֵ
DWORD getRegValue(char* regName);
//�жϸöϵ��Ƿ�ΪӲ���ϵ�,�����,���ظõ�ַ��Ӳ���ϵ��¼��λ��
DWORD isHardwareBP();
//����Ӳ���ϵ��쳣
void handleHard_Bp(DWORD nIndex);
//�ָ����е�int3�ϵ�
void renewAllInt3Bp();
//�ָ����е�Ӳ���ϵ�
void renewAllHardBp();
//�鿴�Ĵ���
void showCurReg();
//�����û�����
void userInput(LPVOID pExpAddr);
//�鿴�ڴ���Ϣ
void showMem(DWORD memAddr);
void showMem2();
//�鿴ջ
void showStack();
//�����ڴ���ʶϵ�
void setMemBreakPoint(DWORD memBpAddr);
//�����ڴ�����쳣
bool handleMemExption(EXCEPTION_RECORD* pExceptionRecord);
//�����ڴ�ϵ�
void renewAllMemBp();
//�ַ����ָ��
std::vector<string> split(const string &str, const string &pattern);
//�޸ļĴ���
void editReg();
//�޸��ڴ�
void editMem();
//��ʾģ����Ϣ
void showModule();
//����EXE�ķ��ŵ�����Ϣ
void onLoadExeSymbol(CREATE_PROCESS_DEBUG_INFO *pInfo);
//����DLL���ŵ�����Ϣ
void onLoadDllSymbol(LOAD_DLL_DEBUG_INFO *pInfo);
//��ʾԴ����Ϣ
void cppDebug();
//��mainϵ�к����¶ϵ�
void bpAtEntryPoint();
//��ȡ�ļ�ĳһ�е�����
char* readLine(char* szPath, int nLine);
//���ݵ�ַ��ȡ������
BOOL GetSymName(HANDLE hProcee, SIZE_T nAddress, CString& strName);
//ɾ��int3�ϵ�
void clearBreakPoint();
//����ڴ�ϵ�
void clearMemBp();
//���Ӳ���ϵ�
void clearHardwareBp();
//�ж�INT3�ϵ��¼���ĳ��INT3�ϵ��Ƿ�����ΪSTEPOVER���õ�
bool inVecStepoverBp(DWORD addr, int& pos);
//���PEB���
void clearProtect();
//API�ϵ�
void setApiBp();
//����ģ�鵼�뵼����
void showModuleExportTable();
//��ʾָ��ģ�鵼����
void showExport(LPVOID pImagebase, IMAGE_NT_HEADERS* pNt);
//��ʾָ��ģ�鵼���
void showImport(LPVOID pImagebase, IMAGE_NT_HEADERS* pNt);
DWORD getProcessPid(wchar_t* szName);
//���ز��
void loadPlugin();
//��ȡ��ȷ�Ĳ������
void travelFolder(CStringA& root);
//���������ϵ�
void setConditionBp(DWORD addr);
//�ж��Ƿ��������ϵ�
bool inConditionTab(LPVOID addr);
//dump�ڴ���Ϣ
bool dumpMemInfo(DWORD startAddr, DWORD nSize);
//ʹ��minidumpwritedump API��dump��Ϣ
void miniDump(EXCEPTION_POINTERS* pExpPointer, bool isCrash = false);
//�޸�ָ����ַ�ķ�������
void editDisasmCode();
//���е����ص�ַ��
void runToRet();
//��¼�ű�
void recordScript();
//��¼�ű�����
void recordOver();
//���нű�
void runScript();
char* getCommand(HANDLE hFile);


