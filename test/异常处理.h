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

//记录被CC覆盖的数据的结构体
typedef struct _ORIGIN_DATA
{
	LPVOID originAddr;
	BYTE data;
}ORIGIN_DATA;
//记录硬件断点结构体
typedef struct _HARD_BREAKPOINT
{
	LPVOID bpAddr;  //断点位置
	int type;		//断点类型,执行,写或者读写
	int reg;		//在DR0-DR3哪一个寄存器中保存
}HARD_BP;
//记录内存断点结构体
typedef struct _MEMORY_BREAKPOINT
{
	DWORD pageBaseAddr;		//分页开始的位置
	DWORD bpAddr;			//内存断点位置
	DWORD oldPageAttribute;	//旧的分页属性
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
//当调试器WaitForDebugEvent收到了被调试进程异常事件的时候调用该函数处理异常
DWORD handleException(EXCEPTION_RECORD* pExceptionRecord);
//恢复被CC覆盖的一个位置的数据
void clearInt3BreakPoint(LPVOID pExceptionAddr);
//通过将TF标志位置1,使得程序只能执行当前EIP指向的这一条指令
//之后立马触发EXCEPTION_SINGLE_STEP异常
void setSingleStepBreakpoint();
//在指定位置下一个int 3断点
void setInt3BreakPoint(LPVOID pointAddr);
//根据传进来的EIP显示该EIP及其以后位置的汇编代码
//nLen代表要显示的汇编代码的条数
void printDisasm(DWORD eip, int nLen = 10);
//根据当前指令地址获取下一条指令的地址,并返回当前指令的前两个字节
DWORD getNextCommandAddr(const DWORD& curCommandAddr, DWORD& nextCommandAddr);
//根据地址下硬件执行断点
void setHardwareBreakPoint(DWORD addr, int nType = 0, int nByteLen = 0);
//判断DR0-DR3中哪个寄存器空闲,返回找到的第一个空闲寄存器,没有则返回-1
int whoIsFree();
//获取某个寄存器的值
DWORD getRegValue(char* regName);
//判断该断点是否为硬件断点,如果是,返回该地址在硬件断点记录的位置
DWORD isHardwareBP();
//处理硬件断点异常
void handleHard_Bp(DWORD nIndex);
//恢复所有的int3断点
void renewAllInt3Bp();
//恢复所有的硬件断点
void renewAllHardBp();
//查看寄存器
void showCurReg();
//处理用户输入
void userInput(LPVOID pExpAddr);
//查看内存信息
void showMem(DWORD memAddr);
void showMem2();
//查看栈
void showStack();
//设置内存访问断点
void setMemBreakPoint(DWORD memBpAddr);
//处理内存访问异常
bool handleMemExption(EXCEPTION_RECORD* pExceptionRecord);
//更新内存断点
void renewAllMemBp();
//字符串分割函数
std::vector<string> split(const string &str, const string &pattern);
//修改寄存器
void editReg();
//修改内存
void editMem();
//显示模块信息
void showModule();
//加载EXE的符号调试信息
void onLoadExeSymbol(CREATE_PROCESS_DEBUG_INFO *pInfo);
//加载DLL符号调试信息
void onLoadDllSymbol(LOAD_DLL_DEBUG_INFO *pInfo);
//显示源码信息
void cppDebug();
//在main系列函数下断点
void bpAtEntryPoint();
//读取文件某一行的内容
char* readLine(char* szPath, int nLine);
//根据地址获取符号名
BOOL GetSymName(HANDLE hProcee, SIZE_T nAddress, CString& strName);
//删除int3断点
void clearBreakPoint();
//清除内存断点
void clearMemBp();
//清除硬件断点
void clearHardwareBp();
//判断INT3断点记录里的某个INT3断点是否是因为STEPOVER设置的
bool inVecStepoverBp(DWORD addr, int& pos);
//清除PEB标记
void clearProtect();
//API断点
void setApiBp();
//解析模块导入导出表
void showModuleExportTable();
//显示指定模块导出表
void showExport(LPVOID pImagebase, IMAGE_NT_HEADERS* pNt);
//显示指定模块导入表
void showImport(LPVOID pImagebase, IMAGE_NT_HEADERS* pNt);
DWORD getProcessPid(wchar_t* szName);
//加载插件
void loadPlugin();
//获取正确的插件函数
void travelFolder(CStringA& root);
//设置条件断点
void setConditionBp(DWORD addr);
//判断是否是条件断点
bool inConditionTab(LPVOID addr);
//dump内存信息
bool dumpMemInfo(DWORD startAddr, DWORD nSize);
//使用minidumpwritedump API来dump信息
void miniDump(EXCEPTION_POINTERS* pExpPointer, bool isCrash = false);
//修改指定地址的反汇编代码
void editDisasmCode();
//运行到返回地址处
void runToRet();
//记录脚本
void recordScript();
//记录脚本结束
void recordOver();
//运行脚本
void runScript();
char* getCommand(HANDLE hFile);


