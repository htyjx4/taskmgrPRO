#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h> //-lpsapi -lversion -Werror
//-std=c++14 -s -Os -flto -fno-rtti -static -liphlpapi
#include <iostream>
#include<cctype>
#include<bits/stdc++.h>
#include"zfh.cpp"
#include"state.cpp"
#pragma comment(lib, "psapi.lib")
using namespace std;
struct task{
	string name,stat,level,owner,minv;
	int pid,thread,base,father;
	int _64bit;
	long long ymhc,ffyhc,fywj,mem,pri;
	//页面缓存 非分页缓存 分页文件 内存 专用工作集
	int cpu;
	int ior,iow,ioo;
	//IO read write other (times)
};
int cmpmode = 4;
// 0:pid 1:name 2:thread 3:base 4:memory
int sl = 29;
int lasterror = 0;
bool is32bit = 0;
map<string,int> colourset;
void color(WORD color,bool error = 0) {
    HANDLE hConsole = GetStdHandle((error ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE));
    SetConsoleTextAttribute(hConsole, color);
}
int goldinput(string s = ">>"){
	int a;
	color(0xe);
	cout<<s;
	cin>>a;
	color(0x7);
	return a;
}
int getbit(){
	SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
		is32bit = 1;
		std::cout << "System is 32-bit or 64-bit (INTELx86)." << std::endl;
    } else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
		is32bit = 0;
		std::cout << "System is 64-bit (AMD64)." << std::endl;
    } else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
		is32bit = 0;
		std::cout << "System is 64-bit (IA64)." << std::endl;
    } else {
    	is32bit = -1;
        std::cout << "Unknown architecture type:"<<sysInfo.wProcessorArchitecture << std::endl;
    }
}
int pxset(){
	cout<<"0:pid 1:name 2:thread 3:base 4:memory\n";
	int a = goldinput();
	cmpmode = a;
	return 0;
}
int is64bit(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return -1;
    }
    BOOL isWow64;
    if (IsWow64Process(hProcess, &isWow64)) {
        CloseHandle(hProcess);
        return !isWow64;
    } else{
        CloseHandle(hProcess);
        return false;
    }
}
std::string GetModulePath(DWORD pid) {
    std::vector<char> path(MAX_PATH);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return "";
    }

    if (EnumProcessModules(hProcess, (HINSTANCE*)&path[0], path.size(), NULL) == 0) {
        CloseHandle(hProcess);
        return "";
    }

    MODULEINFO mi;
    if (GetModuleInformation(hProcess, (HMODULE)&path[0], &mi, sizeof(mi)) == 0) {
        CloseHandle(hProcess);
        return "";
    }

    CloseHandle(hProcess);
    return std::string(&path[0]);
}

std::string GetMinimumWindowsVersion(const std::string& filePath) {
    DWORD dwDummy;
    DWORD dwHandle;
    UINT size = GetFileVersionInfoSizeA(filePath.c_str(), &dwHandle);
    if (size == 0) {
        return "";
    }

    std::vector<char> data(size);
    if (!GetFileVersionInfoA(filePath.c_str(), dwHandle, size, &data[0])) {
        return "";
    }

    VS_FIXEDFILEINFO* versionInfo = nullptr;
    UINT len;
    if (VerQueryValueA(&data[0], "\\", reinterpret_cast<void**>(&versionInfo), &len)) {
        DWORD major = (versionInfo->dwFileVersionMS >> 16) & 0xFFFF;
        DWORD minor = (versionInfo->dwFileVersionMS >> 0) & 0xFFFF;
        return std::to_string(major) + "." + std::to_string(minor);
    }
    return "";
}
string minver(int pid){
    std::string modulePath = GetModulePath(pid);
    if (!modulePath.empty()) {
        std::string minVersion = GetMinimumWindowsVersion(modulePath);
        if (!minVersion.empty()) {
			return minVersion;
        } else {
            return "ERR1";
        }
    } else {
        return "ERR2";
    }
}
int cpuusg(DWORD pid){
    FILETIME creationTime, exitTime, kernelTime, userTime;
    if (!GetProcessTimes(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid), &creationTime, &exitTime, &kernelTime, &userTime)) {
        return -1;
    }
    ULARGE_INTEGER kernel = {0}, user = {0};
    kernel.LowPart = kernelTime.dwLowDateTime;
    kernel.HighPart = kernelTime.dwHighDateTime;
    user.LowPart = userTime.dwLowDateTime;
    user.HighPart = userTime.dwHighDateTime;
    double totalTime = (kernel.QuadPart + user.QuadPart) / 10000.0;
    int cpuUsage = (user.QuadPart / totalTime)/100;
    if(cpuUsage<0) return -1;
    return cpuUsage;
}
PROCESS_MEMORY_COUNTERS_EX chkmem(DWORD pid){
    PROCESS_MEMORY_COUNTERS_EX pmc;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
    	lasterror = 1;
    }
    else{
	    if (GetProcessMemoryInfo(hProcess, (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof(pmc))) {
	    	lasterror = 0;
	    } else {
	    	lasterror = 2;
	    }
	}

	CloseHandle(hProcess);
    return pmc;
}
bool iostat(DWORD pid, IO_COUNTERS& ioCounters) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        //cerr << "Failed to open process" << endl;
        return false;
    }

    if (!GetProcessIoCounters(hProcess, &ioCounters)) {
        //cerr << "Failed to get IO counters" << endl;
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hProcess);
    return true;
}
string processstat(DWORD processId) {
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, processId);
    if (processHandle == NULL) {
    	CloseHandle(processHandle);
        return "拒绝访问";
    }

    DWORD result = WaitForSingleObject(processHandle, 0);
    CloseHandle(processHandle);

    if (result == WAIT_TIMEOUT) {
        return "运行";
    } else if (result == WAIT_OBJECT_0) {
        return "已终止";
    } else if (result == WAIT_ABANDONED) {
        return "已挂起";
    } else if (result == WAIT_FAILED) {
        return "失败";
    } else {
        return "未知";
    }
}
bool GetProcessIntegrityLevel(DWORD processId, DWORD &integrityLevel) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return false;
    }
    DWORD mandatoryPolicy;
    DWORD returnLength;
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &returnLength) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }
    TOKEN_MANDATORY_LABEL *pTokenLabel = (TOKEN_MANDATORY_LABEL*)new BYTE[returnLength];
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenLabel, returnLength, &returnLength)) {
        delete[] (BYTE*)pTokenLabel;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }
    integrityLevel = *GetSidSubAuthority(pTokenLabel->Label.Sid, 0);
    delete[] (BYTE*)pTokenLabel;
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return true;
}
string processlevel(int pid){
	DWORD l;
	if(GetProcessIntegrityLevel(pid, l)){
		switch(l){
			case 0x1000:return"LOW";
			case 0x2000:return"MID";
			case 0x3000:return"HIGH";
			case 0x4000:return"SYS";
		}
		return "ERR";
	}
	else{
		return "FAIL";
	}
}
class ProcessCpuMonitor {
public:
    ProcessCpuMonitor(DWORD pid) : pid_(pid) {
        hProcess_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid_);
    }
    ~ProcessCpuMonitor() {
        if (hProcess_) CloseHandle(hProcess_);
    }
    float GetUsage() {
        FILETIME createTime, exitTime, kernelTime, userTime;
        if (!GetProcessTimes(hProcess_, &createTime, &exitTime, &kernelTime, &userTime))
            return -1;

        ULONGLONG currentKernel = *(ULONGLONG*)&kernelTime;
        ULONGLONG currentUser = *(ULONGLONG*)&userTime;
        ULONGLONG delta = (currentKernel + currentUser) - (lastKernel_ + lastUser_);
        ULONGLONG timePassed = GetTickCount() - lastTick_;
        lastTick_ = GetTickCount();
        lastKernel_ = currentKernel;
        lastUser_ = currentUser;

        if (timePassed == 0) return 0.0f;
        return (delta / 10000.0f) / timePassed * 100.0f;
    }

private:
    DWORD pid_;
    HANDLE hProcess_ = nullptr;
    ULONGLONG lastKernel_ = 0, lastUser_ = 0;
    ULONGLONG lastTick_ = 0;
};
bool processowner(DWORD pid, string& username) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        //cerr << "OpenProcess failed with error: " << GetLastError() << endl;
        return false;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        //cerr << "OpenProcessToken failed with error: " << GetLastError() << endl;
        CloseHandle(hProcess);
        return false;
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        //cerr << "GetTokenInformation failed with error: " << GetLastError() << endl;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    TOKEN_USER* pTokenUser = (TOKEN_USER*)new char[dwSize];
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        //cerr << "GetTokenInformation failed with error: " << GetLastError() << endl;
        delete[] pTokenUser;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }
    char usernameW[256];
    char domainW[256];
    DWORD cbName = sizeof(usernameW);
    DWORD cbDomain = sizeof(domainW);
    SID_NAME_USE snu;
    if (!LookupAccountSidA(NULL, pTokenUser->User.Sid, usernameW, &cbName, domainW, &cbDomain, &snu)) {
        //cerr << "LookupAccountSidW failed with error: " << GetLastError() << endl;
        delete[] pTokenUser;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }
    username = usernameW;
    delete[] pTokenUser;
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return true;
}
int IsProcessSuspended(DWORD pid) {
    return  getprocessstate(pid);
}
string getgcmode(int pid){
	int a = IsProcessSuspended(pid);
	if(a==1) return "已挂起";
	else if(a==0) return "正常运行";
	else return to_string(a);
}
vector<task> listtask() {
    vector<task>v;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        cerr << "listtask:CreateToolhelp32Snapshot failed" << endl;
        return v;
    }
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        cerr << "listtask:Process32First failed" << endl;
        CloseHandle(hProcessSnap);
        return v;
    }
    do {
		task t;
		t.pid = pe32.th32ProcessID;
		t.name = pe32.szExeFile;
		t.thread = pe32.cntThreads;
		t.base = pe32.pcPriClassBase;
		t.father = pe32.th32ParentProcessID;
		if(is32bit == 0) t._64bit = is64bit(t.pid);
		else t._64bit = 0;
		t.stat = getgcmode(t.pid);
		t.cpu = cpuusg(t.pid);
		t.level = processlevel(t.pid);
		PROCESS_MEMORY_COUNTERS_EX pmc = chkmem(t.pid);
		if(!lasterror){
			t.ymhc = pmc.QuotaPagedPoolUsage/1024;
			t.ffyhc = pmc.QuotaNonPagedPoolUsage/1024;
			t.fywj = pmc.PagefileUsage/1024;
			t.mem = pmc.WorkingSetSize/1024;
			t.pri = pmc.PrivateUsage/1024;
		}
		else{
			t.ymhc = -1;
			t.ffyhc = -1;
			t.fywj = -1;
			t.mem = -1;
			lasterror = 0;
		}
	    IO_COUNTERS ioCounters;
	    if (iostat(t.pid, ioCounters)) {
	    	t.ior =ioCounters.ReadOperationCount;
	    	t.iow =ioCounters.WriteOperationCount;
	    	t.ioo =ioCounters.OtherOperationCount;
	    }
	    else{
	    	t.ior=-1;t.iow=-1;t.ioo=-1;
	    }
	    string own;
	    if(processowner(t.pid,own)){
	    	t.owner = own;
		}
		else{
			t.owner = "";
		}
    	ProcessCpuMonitor monitor(t.pid);
        t.cpu = monitor.GetUsage();
        t.minv = minver(t.pid);
		v.push_back(t);
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return v;
}
string strsetw(string s,int w,bool nob = 0){
	if(s.size()>w) return s.substr(0,w-3)+"...";
	else if(!nob){
		string t=s;
		for(int i = 0;i<w-s.size();i++) t+=" ";
		return t;
	}
	else{
		return s;
	}
}
string lower(string s){
	string lowerStr;
    for (char c : s) {
        lowerStr += tolower(c);
    }
    return lowerStr;
}
void setmap(){
	colourset["sduedu.exe"]=0x4f;
	colourset["studentmain.exe"]=0x4f;
	colourset["chrome.exe"]=0xAF;
	colourset["msedge.exe"]=0xAF;
	colourset["devcpp.exe"]=0xAF;
	colourset["svchost.exe"]=0x28;
	colourset["runtimebroker.exe"]=0x28;
	colourset["dllhost.exe"]=0x28;
	colourset["textinputhost.exe"]=0x28;
	colourset["searchhost.exe"]=0x28;
	colourset["explorer.exe"]=0x3F;
	colourset["smss.exe"]=0x37;
	colourset["csrss.exe"]=0x37;
	colourset["wininit.exe"]=0x37;
	colourset["services.exe"]=0x37;
	colourset["system"]=0x37;
	colourset["[system process]"]=0x37;
	colourset["secure system"]=0x37;
	colourset["winlogon.exe"]=0x37;
	colourset["registry"]=0x37;
	colourset["wudfhost.exe"]=0x37;
	colourset["dwm.exe"]=0x37;
	colourset["fontdrvhost.exe"]=0x37;
	colourset["lsass.exe"]=0x37;
	colourset["lsaiso.exe"]=0x37;
	colourset["hipsdaemon.exe"]=0xE0;
	colourset["hipstray.exe"]=0xE0;
	colourset["notepad.exe"]=0xaf;
	colourset["taskmgr.exe"]=0xaf;
}
int putmem(long long usg,bool unavi){
	if(usg<0 || unavi){
		cout<<"      ";return 0;
	}
	int kb = usg;
	if(usg>8192){
		int mb = usg/1024;
		color(0xb);
		printf("%5dM",mb);
	}
	else{
		color(0x7);
		printf("%5dK",kb);
	}
}
int putnum(long long b){
	if(b>=10000){
		long long kb = b/1000;
		color(0xb);
		if(kb>=10000){
			long long mb = kb/1000;
			printf("%4dm",mb);
		}
		else{
			printf("%4dk",kb);
		}
	}
	else if(b<0){
		color(0x7);
		cout<<"     ";
	}
	else{
		color(0x7);
		printf("%5d",b);
	}
}
class _basicchoose{
private:
	const int choosenum = 9;
	bool usg[20] = {1,1,1,1,1,1,1,1,0};
	const string zhcn[20] = {
	"进程信息","体系结构","内存","状态",
	"IO","CPU","级别","用户",
	"最低版本","","",""};
public:
	bool getset(const int num){
		return usg[num];
	}
	string getcn(const int num){
		return zhcn[num];
	}
	void putset(){
		for(int i = 0;i<choosenum;i++){
			if(!getset(i)) continue;
			cout<<getcn(i)<<" ";
		}
		cout<<endl;
	}
	void setchoose(){
		int a=1;
		cout<<"=====设置选项=====\n";
		while(a!=0){
			cout<<"0.退出 1.修改设置 2.显示设置\n";
			a = goldinput();
			if(a==2){
				for(int i = 0;i<choosenum;i++){
					cout<<"选项\'"<<getcn(i)<<"\'(编号"<<i<<")的设定为 "<<(getset(i)?"True":"False")<<endl;
				}
			}
			if(a==1){
				int b;
				b = goldinput("输入编号:");
				usg[b] = !usg[b];
				cout<<"选项\'"<<getcn(b)<<"\'(编号"<<b<<")的设定已修改为 "<<(getset(b)?"True":"False")<<endl;
			}
		}
	}
};
_basicchoose putset;
int puttask(task t){
	int col = 0x07;
	string namel = lower(t.name);
	if(colourset[namel]!=0) col = colourset[namel];
	else if(t._64bit==-1){
		col = 0x8;
	}
	color(col);cout<<strsetw(t.name,sl);
	color(0x07);//cout<<" ";
	if(putset.getset(0)){
		printf("%5d%4d%3d%5d",t.pid,t.thread,t.base,t.father);
	}
	int bits = -2;
	switch(t._64bit){
		case 1:
			color(0x27);
			bits = 64;
			break;
		case 0:
			color(0x97);
			bits = 32;
			break;
		case -1:
			color(0x47);
			bits = -1;
			break;
	}
	if(putset.getset(1)){
		printf("%2d",bits);
		color(0x07);cout<<" ";
	}
	bool unavi = t._64bit==-1;
	if(putset.getset(2)){
		putmem(t.ymhc,unavi);
		putmem(t.ffyhc,unavi);
		putmem(t.fywj,unavi);
		putmem(t.mem,unavi);
		putmem(t.pri,unavi);
	}
	//printf("%7lldk%7lldk%7lldk%7lldk%7lldk",t.ymhc,t.ffyhc,t.fywj,t.mem,t.pri);
	//cout<<" ";
	if(putset.getset(3)){
		if(t.stat=="运行")color(0xa7);
		else if(t.stat=="正常运行")color(0x27);
		else if(t.stat=="已终止")color(0x87);
		else if(t.stat=="已挂起")color(0x67);
		else if(t.stat=="失败")color(0xc7);
		else if(t.stat=="拒绝访问")color(0xc7);
		else color(0x17);
		cout<<strsetw(t.stat,8);
	}
	if(putset.getset(4)){
		putnum(t.ior);//cout<<"/";
		putnum(t.iow);//cout<<"/";
		putnum(t.ioo);
		color(0x07);
	}
	if(putset.getset(5)){
		if(t.cpu>=0)printf("%2d%%",(int)t.cpu);
		else cout<<"   ";
	}
	if(putset.getset(6)){
		if(t.level=="LOW") color(0x27);
		else if(t.level=="MID") color(0x97);
		else if(t.level=="HIGH") color(0x67);
		else if(t.level=="SYS") color(0x47);
		else color(0x87);
		cout<<strsetw(t.level,4);
	}
	color(0x07);
	if(putset.getset(7)){
		cout<<strsetw(t.owner,11);
	}
	if(putset.getset(8)){
		cout<<strsetw(t.minv,8);
	}
	cout<<"\n";
	return 0;
}
void printname(){

}
int printtask(vector<task>t){
	cout<<"task count:"<<t.size()<<"\n";
	for(int i = 0;i<t.size();i++){
		color(0xe);
		if(i%10==0)putset.putset();
		//if(i%10==0)cout<<"程序名 PID 线程 优先级 父进程 64位 页面缓存 非分页缓存 分页文件 内存 专用工作集 状态 IO读 写 其他 CPU 级别 用户\n";
		color(0x7);
		puttask(t[i]);
	}
}
bool tskcmp(task a,task b){
	switch (cmpmode){
		case 0:
			return a.pid<b.pid;
		case 1:
			return a.name<b.name;
		case 2:
			return a.thread<b.thread;
		case 3:
			return a.base<b.base;
		case 4:
			return a.mem>b.mem;
	}
}
int print(){
	cout<<"preparing\n";
	vector<task> v = listtask();
	cout<<"sorting\n";
    sort(v.begin(),v.end(),tskcmp);
	cout<<"printing\n";
    printtask(v);
}
int init(){
	getbit();
	setmap();
}
void supthread(DWORD processId){
	HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, processId);
    if (hProcess == NULL) {
        cerr << "无法打开进程" << endl;
        return;
    }
    if (SuspendThread(hProcess) == (DWORD)-1) {
        cerr << "无法挂起进程" << endl;
    } else {
        cout << "进程已挂起" << endl;
    }
    CloseHandle(hProcess);
}
void resthread(DWORD processId){
	HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, processId);
    if (hProcess == NULL) {
        cerr << "无法打开进程" << endl;
        return;
    }
    if (ResumeThread(hProcess) == (DWORD)-1) {
        cerr << "无法恢复进程" << endl;
    } else {
        cout << "进程已成功恢复" << endl;
    }
    CloseHandle(hProcess);
}
int supendpr(){
	int pid;
	pid = goldinput("input pid:");
	supthread(pid);
}
int resumepr(){
	int pid;
	pid = goldinput("input pid:");
	resthread(pid);
}
int terminatepr(){
	int pid;
	pid = goldinput("input pid:");
	DWORD processId = pid;
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        cerr << "OpenProcess failed (" << GetLastError() << ")\n";
        return 1;
    }
    if (TerminateProcess(hProcess, 0)) {
        cout << "Process terminated successfully\n";
    } else {
        cerr << "TerminateProcess failed (" << GetLastError() << ")\n";
    }
    CloseHandle(hProcess);
    return 0;
}
BOOL ctrle() {
    if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
        if (GetAsyncKeyState('E') & 0x8000) {
            return TRUE;
        }
        else{
    		return FALSE;
		}
    }
    return FALSE;
}
int cctv(){
	int pid;
	pid = goldinput("input pid:");
	bool f  = 0;
	cout<<"ctrl + E to stop\n";
	while(f==0){
		bool fl = 0;
		vector<task> v = listtask();
		for(task t : v){
			if(t.pid==pid){
				puttask(t);
				fl=1;
				break;
			}
		}
		if(fl==0){
			cout<<"Underfind process\n";
			break;
		}
		for(int i = 0;i<10;i++){
			Sleep(50);
			if(ctrle()) f = 1;
		}
	}
}
int about(){
	int r = MessageBox(NULL,"字符世界55大队 hty\n点击\'是\'跳转 \'否\'下载oj崩坏器\n字符软件集团","字符软件集团-任务管理器pro",MB_YESNOCANCEL|MB_ICONINFORMATION);
	cout<<"ret id:"<<r<<endl;
	switch(r){
		case IDYES:
			system("start http://123.60.188.246/group/1025");
			break;
		case IDNO:
			system("start https://objectstorageapi.hzh.sealos.run/siztgh66-public/TAT_UAT_x86.zip");
	}
}
int main() {
	init();
    int a=1;
	do{
		cout<<"0.exit 1.tasklist 2.terminate 3.supend 4.resume 5.cctv 6.setting 7.painting 8.about\n";
		a = goldinput();
		if(a==1){
			print();
		}
		if(a==2){
			terminatepr();
		}
		if(a==3){
			supendpr();
		}
		if(a==4){
			resumepr();
		}
		if(a==5){
			cctv();
		}
		if(a==6){
			cout<<"1.显示设置 2.排序设置\n";
			int b = goldinput();
			if(b==1)putset.setchoose();
			else pxset();
		}
		if(a==7){
			zfh();
		}
		if(a==8){
			about();
		}
	}
	while(a);
    return 0;
}
