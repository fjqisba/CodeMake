
// CodMakeDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "CodMake.h"
#include "CodMakeDlg.h"
#include "afxdialogex.h"
#include "beaengine/beaengine.h"
#include "Elib.h"
#include <string>
#include <math.h>

using namespace std;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif




void ReadHex(ULONG addr,int len,char* hextext) {   //返回文本形式  
	byte *buffer = new byte[len];
	memset(buffer, 0, len);
	ReadProcessMemory((HANDLE)-1, (LPCVOID)addr, buffer, len, NULL);
	for (int n = 0;n < len;n++) {
		sprintf(hextext+n*2, "%02X", buffer[n]);
	}
	delete[]buffer;
}

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CCodMakeDlg 对话框



CCodMakeDlg::CCodMakeDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CCodMakeDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCodMakeDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_output);
	DDX_Control(pDX, IDC_STATIC1, m_libname);
}

BEGIN_MESSAGE_MAP(CCodMakeDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_DROPFILES()
END_MESSAGE_MAP()


// CCodMakeDlg 消息处理程序

BOOL CCodMakeDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码
	

	char bufBeaInfo[128] = { 0 };
	wsprintfA(bufBeaInfo, "CodeMake3.0  BeaEngineVersion = %s",BeaEngineVersion());

	SetWindowTextA(m_hWnd,bufBeaInfo);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CCodMakeDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CCodMakeDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CCodMakeDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

static inline void*
OffsetPointer(void* data, ptrdiff_t offset) {
	return (void*)((uintptr_t)data + offset);
}

INT CCodMakeDlg::IsRelocated(ULONG addr,int len) {    //-1表示无重定位数据,返回重定位偏移字节
	for (UINT n = 0;n < len - 3;n++) {
		if (m_relocation[addr + n] == true) {
			return n;
		}
	}
	return -1;
}



BOOL CCodMakeDlg::GenerateRelocationMap(unsigned char* pdll, ptrdiff_t delta)  //生成重定位地址表
{
	unsigned char *codeBase = pdll;
	PIMAGE_BASE_RELOCATION relocation;
	PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)pdll;
	PIMAGE_NT_HEADERS pNtHead = (PIMAGE_NT_HEADERS)(pdll + pDosHead->e_lfanew);//NT头

	int nSection = pNtHead->FileHeader.NumberOfSections;
	DWORD tmp = (DWORD)pNtHead + sizeof(IMAGE_FILE_HEADER) + pNtHead->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_NT_SIGNATURE);
	PIMAGE_SECTION_HEADER	pSection = (PIMAGE_SECTION_HEADER)tmp;//区段
	DWORD	dwExeSectionSize;
	for (int i = 0; i < nSection; i++)
	{
		if (pSection->Characteristics & PAGE_EXECUTE_READ)
		{
			dwExeSectionSize = (DWORD)(codeBase + pSection->Misc.VirtualSize);
		}
	}

	PIMAGE_DATA_DIRECTORY directory = (PIMAGE_DATA_DIRECTORY)&pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD	dwIatStart = pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + (DWORD)codeBase;
	DWORD	dwIatEnd = dwIatStart + pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

	if (directory->Size == 0) {
		return (delta == 0);
	}

	relocation = (PIMAGE_BASE_RELOCATION)(codeBase + directory->VirtualAddress);
	for (; relocation->VirtualAddress > 0;) {
		DWORD i;
		unsigned char *dest = codeBase + relocation->VirtualAddress;
		unsigned short *relInfo = (unsigned short*)OffsetPointer(relocation, IMAGE_SIZEOF_BASE_RELOCATION);
		for (i = 0; i < ((relocation->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
			// the upper 4 bits define the type of relocation
			int type = *relInfo >> 12;
			// the lower 12 bits define the offset
			int offset = *relInfo & 0xfff;

			switch (type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				// skip relocation
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				// change complete 32 bit address
			{
				ULONG *patchAddrHL = (DWORD *)(dest + offset);
				DWORD dwOldProtect;
				VirtualProtect(patchAddrHL, sizeof(void*), PAGE_EXECUTE_READWRITE, &dwOldProtect);
				m_relocation[(ULONG)patchAddrHL] = true;
			}
			break;

#ifdef _WIN64
			case IMAGE_REL_BASED_DIR64:
			{
				ULONGLONG *patchAddr64 = (ULONGLONG *)(dest + offset);
				*patchAddr64 += (ULONGLONG)delta;
			}
			break;
#endif
			default:
				//printf("Unknown relocation: %d\n", type);
				break;
			}
		}

		// advance to next relocation block
		relocation = (PIMAGE_BASE_RELOCATION)OffsetPointer(relocation, relocation->SizeOfBlock);
	}
	return TRUE;
}

BOOL CCodMakeDlg::GenerateIATMap(unsigned char* pdll) {

	PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)pdll;
	PIMAGE_NT_HEADERS pNtHead = (PIMAGE_NT_HEADERS)(pdll + pDosHead->e_lfanew);//NT头

	ULONG importoffset = pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (importoffset == NULL) {
		return false;
	}
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(importoffset + (ULONG)pdll);     //获取导入表
	
	for (; importDesc->OriginalFirstThunk > 0;) {
		string dllname = (char*)(importDesc->Name + (ULONG)pdll);
		dllname.erase(dllname.find_first_of(".", 0)+1);
		ULONG* Funcoffset = (ULONG*)(importDesc->OriginalFirstThunk + pdll);
		ULONG FuncAddr = importDesc->FirstThunk + (ULONG)pdll;
		for (; *(ULONG*)Funcoffset> 0;) {
			if (*Funcoffset <= 0x70000000) {   //偏移应在合理范围内
				m_import[FuncAddr] = dllname + (char*)(*Funcoffset + (ULONG)pdll + 2);   //生成IAT表
			}
			Funcoffset++;
			FuncAddr = FuncAddr + 4;
		}		
		importDesc++;
	}

	return true;
}

INT CCodMakeDlg::Findprocend(ULONG FuncStartAddr,string& FuncText) {   //传入子程序地址,返回值对应不同的分析结果,1代表分析结束
	DISASM asmcode = {0};
	asmcode.EIP = FuncStartAddr;

	CallLevel = CallLevel + 1; 

	static char temp[32];

	ULONG MaxAddr = 0;

	for (;;) {
		int len = Disasm(&asmcode);

		if (len <= 0) {
			break;
		}

		for (int n = 0;n < len;n++) {
			m_block[asmcode.EIP + n] = true;    //已经分析过的代码块
		}

		if (m_relocation[asmcode.EIP]) {	//第一个字节就是重定位,这是不可能的,说明把数据当做代码处理了
			FuncText.append("????????");
			asmcode.EIP = asmcode.EIP + 4;
			continue;
		}

		if (len >= 5) {					//汇编代码长度大于等于5的指令基本都是复杂指令,不如分个类

			int offset = IsRelocated(asmcode.EIP, len);		 //判断是否存在重定位
			if (offset != -1) {								 //存在重定位则模糊处理重定位字节
				if (strcmp(asmcode.Instruction.Mnemonic,"jmp ")==0 && !m_import[asmcode.Argument1.Memory.Displacement].empty()) {        //jmp类型IAT跳转
					FuncText.append("[" + m_import[asmcode.Argument1.Memory.Displacement] + "]");
					CallLevel = CallLevel - 1;
					return 1;
				}
				if (strcmp(asmcode.Instruction.Mnemonic, "call ") == 0 && !m_import[asmcode.Argument1.Memory.Displacement].empty()) {	 //call类型IAT跳转
					FuncText.append("<[" + m_import[asmcode.Argument1.Memory.Displacement] + "]>");
					asmcode.EIP = asmcode.EIP + len;
					continue;
				}

				ReadHex(asmcode.EIP, len, temp);
				if (len>=9 && m_relocation[asmcode.EIP + offset+4]) {  //存在双重定位
					for (int n = 0;n < 16;n++) {
						temp[(offset * 2) + n] = 0x3F;
					}
				}
				else
				{
					for (int n = 0;n < 8;n++) {
						temp[(offset * 2) + n] = 0x3F;
					}
				}
				
				FuncText.append(temp);
				asmcode.EIP = asmcode.EIP + len;
				continue;
			}
			else if (asmcode.Instruction.BranchType != 0 && asmcode.Instruction.AddrValue != 0) {		//jmp,je,call一类指令,且有跳转地址
				if (asmcode.Instruction.BranchType == 11) {		//长jmp指令,例如 jmp $+100E
					if ((FuncStartAddr > asmcode.Instruction.AddrValue || asmcode.Instruction.AddrValue > MaxAddr) && m_block[asmcode.Instruction.AddrValue] == false && abs((long)(asmcode.Instruction.AddrValue-asmcode.EIP))>5) {
						if (asmcode.Instruction.AddrValue < (ULONG)hLib || asmcode.Instruction.AddrValue >= (ULONG)hLib + SectionSize) {  //异常汇编或者VMP代码?
							FuncText.append("E9????????");
							CallLevel = CallLevel - 1;
							return 1;
						}
						FuncText.append("-->");
						MaxAddr = 0;
						asmcode.EIP = asmcode.Instruction.AddrValue;
					}
					else
					{
						ReadHex(asmcode.EIP, len, temp);
						FuncText.append(temp);
						asmcode.EIP = asmcode.EIP + len;
					}
					continue;
				}
				else if (asmcode.Instruction.BranchType == 12 && asmcode.Instruction.Opcode == 232)		//E8 call指令,例如 call 0x401000
				{
					if (CallLevel >= CALL_LEVEL){  //默认限定为3层,超过3层的CALL将不再追踪,全部化为E8 ?? ?? ?? ??
						FuncText.append("E8????????");
						asmcode.EIP = asmcode.EIP + len;
						continue;
					}
					string calladdr = to_string(asmcode.Instruction.AddrValue);
					if (!m_call[calladdr]) {  //第一次识别该函数
						string calltext;
						m_call[calladdr] = true;                 //防止递归
						Findprocend(asmcode.Instruction.AddrValue, calltext);
						WriteFile(hFile, (calladdr + ":" + calltext + "\r\n").c_str(), calladdr.length() + 3 + calltext.length(), &dwWritten, NULL);
					}
					FuncText.append("<" + calladdr + ">");
					asmcode.EIP = asmcode.EIP + len;
					continue;
				}
				else   //分支指令,例如 je $+100E
				{
					MaxAddr = max(MaxAddr, asmcode.Instruction.AddrValue);
					ReadHex(asmcode.EIP, len, temp);
					FuncText.append(temp);
					asmcode.EIP = asmcode.EIP + len;
					continue;
				}
			}
			else
			{
				ReadHex(asmcode.EIP, len, temp);
				FuncText.append(temp);
				asmcode.EIP = asmcode.EIP + len;
				continue;
			}
		}
		else {					//汇编代码长度小于5
			if (asmcode.Instruction.BranchType != 0 && asmcode.Instruction.AddrValue != 0) {		//属于jmp,je一类指令,且有跳转地址
				if (asmcode.Instruction.BranchType == 11 && asmcode.EIP>=MaxAddr) {    //有的函数短jmp指令为终结
					ReadHex(asmcode.EIP, len, temp);
					FuncText.append(temp);
					CallLevel = CallLevel - 1;
					return 1;
				}
				MaxAddr = max(MaxAddr, asmcode.Instruction.AddrValue);
				ReadHex(asmcode.EIP, len, temp);
				FuncText.append(temp);
				asmcode.EIP = asmcode.EIP + len;
				continue;
			}
			else if (asmcode.Instruction.BranchType == 13 && asmcode.EIP >= MaxAddr) {
				ReadHex(asmcode.EIP, len, temp);
				FuncText.append(temp);
				CallLevel = CallLevel - 1;
				return 1;
			}
			else
			{
				ReadHex(asmcode.EIP, len, temp);
				FuncText.append(temp);
				asmcode.EIP = asmcode.EIP + len;
				continue;
			}
		}
	}

	


	return 0;
}


bool MatchCode(unsigned char *pSrc1,unsigned char *pSrc2,int nLen)
{
	for (int i = 0; i < nLen; i++)
	{
		if (pSrc1[i] != pSrc2[i])
			return false;
	}
	return true;
}

void CCodMakeDlg::DebugMessage(char *format, ...)
{
	USES_CONVERSION;
	char buf[MAX_PATH] = { 0 };
	va_list st;
	va_start(st, format);
	vsprintf_s(buf, format, st);
	va_end(st);
	m_output.SetCurSel(m_output.InsertString(-1, A2W(buf)));
}


void CCodMakeDlg::MakeCode(LPWSTR lpFile)
{	
	USES_CONVERSION;
	CString strLibName,strLibVer,strGuid,strComCount;
	CString	strFile(lpFile);
	if (strFile.Right(4).CompareNoCase(L".fne") != 0)
	{
		AfxMessageBox(L"请拖入 .fne 易语言支持库文件!");
		return;
	}

	hLib = LoadLibrary(strFile);
	if (!hLib)
	{
		AfxMessageBox(L"加载DLL文件失败!");
		return;
	}

	MEMORY_BASIC_INFORMATION MB;
	if (VirtualQuery(hLib+4096, &MB, sizeof(MB)) == 0) {
		AfxMessageBox(L"查询页面失败!");
		return;
	}
	SectionSize = MB.RegionSize;

	typedef PLIB_INFO(WINAPI* FnGetNewInf)(void);
	FnGetNewInf pFnGetNewInf = (FnGetNewInf)GetProcAddress(hLib, "GetNewInf");
	if (!pFnGetNewInf)
	{
		AfxMessageBox(L"导出接口 GetNewInf 不存在!");
		return;
	}

	PLIB_INFO pLibInfo = pFnGetNewInf();
	
	strLibName.Format(L"支持库名称: %s", A2W((char*)pLibInfo->m_szName));
	SetDlgItemTextW(IDC_STATIC1, strLibName);

	strLibVer.Format(L"%1d.%1d", pLibInfo->m_nMajorVersion,pLibInfo->m_nMinorVersion);
	SetDlgItemTextW(IDC_STATIC2, (CString)L"版本:" + strLibVer);

	strComCount.Format(L"命令总数: %d", pLibInfo->m_nCmdCount);
	SetDlgItemTextW(IDC_STATIC5, strComCount);

	strGuid.Format(L"%s", A2W((char*)pLibInfo->m_szGuid));
	SetDlgItemTextW(IDC_STATIC3, (CString)L"GUID: " + strGuid);

	//————————————————————————————————————

	vector<string> Original_array;  //原始命令数组
	vector<string> Named_array;    //处理自定义数据类型

	CString	strWorkPath;
	WCHAR wcsCurPath[MAX_PATH] = { 0 };
	GetCurrentDirectory(MAX_PATH, wcsCurPath);
	strWorkPath = wcsCurPath;
	strWorkPath += L"\\"; strWorkPath += strGuid;
	CreateDirectory(strWorkPath, NULL);

	PCMD_INFO  pCmd_Info = pLibInfo->m_pBeginCmdInfo;

	for (int n = 0;n < pLibInfo->m_nCmdCount;n++) {
		Original_array.push_back((char*)pCmd_Info->m_szName);
		pCmd_Info++;
	}

	Named_array = Original_array;
	PLIB_DATA_TYPE_INFO pDataTypeInfo = pLibInfo->m_pDataType;
	for (int n = 0;n < pLibInfo->m_nDataTypeCount;n++) {
		LPINT CmdsIndex = pDataTypeInfo->m_pnCmdsIndex;
		for (int m = 0;m < pDataTypeInfo->m_nCmdCount;m++) {
			Named_array[*CmdsIndex] = (char*)pDataTypeInfo->m_szName;
			Named_array[*CmdsIndex].append(".");
			Named_array[*CmdsIndex].append(Original_array[*CmdsIndex]);
			CmdsIndex++;
		}
		pDataTypeInfo++;
	}


	PCMD_INFO  pCmd = pLibInfo->m_pBeginCmdInfo;
	LPINT pFunc = (LPINT)pLibInfo->m_pCmdsFunc;
	//————————————————————————————————————
	//                     生成一份源码

	/*string ECODE;
	ECODE.append(".局部变量 整数, 整数型\r\n");
	ECODE.append(".局部变量 文本, 文本型\r\n");
	ECODE.append(".局部变量 字节集, 字节集\r\n");
	for (int i = 0;i < pLibInfo->m_nCmdCount;i++) {
		if (*pFunc == NULL) {           //过滤空函数,例如 如果命令
			pCmd++;continue;
		}
		if (pCmd->m_wState == 32772) { //无效命令,从一些函数的属性中分析得出的结果
			pCmd++;continue;
		}

		PARG_INFO arg = pCmd->m_pBeginArgInfo;
		string Efunc = (char*)pCmd->m_szName;
		Efunc = Efunc + '(';
		for (int n = 0;n < pCmd->m_nArgCount;n++) {
			switch (arg->m_dtDataType)
			{
			case 0x80000000:   //通用型
				Efunc.append("整数,");
				break;
			case 0x80000005:   //字节集
				Efunc.append("字节集,");
				break;
			case 0x80000006:   //子程序指针
				Efunc.append("&子程序,");
				break;
			case 0x80000301:   //整数型
				Efunc.append("整数,");
				break;
			case 0x80000004:   //文本型
				Efunc.append("文本,");
				break;
			case 0x80000002:   //逻辑型
				Efunc.append("真,");
				break;
			default:
				DebugMessage("%s-%X", pCmd->m_szName, arg->m_dtDataType);
				break;
			}
			arg++;
		}
		if (Efunc[Efunc.length() - 1] == ',') {
			Efunc.erase(Efunc.length() - 1);
		}
		
		Efunc = Efunc + ')';
		DebugMessage("%s", Efunc.c_str());
		ECODE.append(Efunc + "\r\n");
		pCmd++;
	}

	ECODE.append(".子程序 子程序\r\n");

	//置入剪辑版
	HGLOBAL hClip;
	if (OpenClipboard()) {
		EmptyClipboard();
		hClip = GlobalAlloc(GMEM_MOVEABLE, ECODE.length() + 1);
		char *buff;
		buff = (char*)GlobalLock(hClip);	//锁定内存
		strcpy(buff, ECODE.c_str());
		GlobalUnlock(hClip);
		SetClipboardData(CF_TEXT, hClip);
		CloseClipboard();
	}
	return;*/
	
	//————————————————————————————————————
	GenerateRelocationMap((unsigned char*)hLib, 0);  //生成一份重定位地址表

	GenerateIATMap((unsigned char*)hLib);   //生成一份IAT表

	DebugMessage("> 开始生成特征库===========================");
	//————————————————————————————————————
	
	CString strTargetFile = strWorkPath; strTargetFile += L"\\";
	strTargetFile += strLibVer;
	strTargetFile += L".Esig";

	hFile = CreateFile(strTargetFile, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		AfxMessageBox(L"创建sig文件失败! 当前目录不可写 或者没有管理员权限");
		return;
	}

	for (int i = 0; i < pLibInfo->m_nCmdCount; i++)
	{
		if (*pFunc == NULL){           //过滤空函数,例如 如果命令
			pCmd++;pFunc++;continue;
		}
		if (pCmd->m_wState == 32772) { //无效命令,从一些函数的属性中分析得出的结果
			pCmd++;pFunc++;continue;
		}

		string FuncName = Named_array[i];
		string FuncText;

		m_block.clear();
		Findprocend(*pFunc, FuncText);

		m_FuncOk[FuncName]= FuncText;

		DebugMessage("%s", FuncName.c_str());

		pCmd++; pFunc++;
	}

	DebugMessage("生成完毕!命令有效数为:%d",m_FuncOk.size());	

	//—————————写入文件————————————————
	WriteFile(hFile, "******\r\n", 8, &dwWritten, NULL);
	
	map<string, string>::iterator it;
	it = m_FuncOk.begin();
	while (it != m_FuncOk.end()) {
		WriteFile(hFile, (it->first + ":" + it->second + "\r\n").c_str(), it->first.length() + 3 + it->second.length(), &dwWritten, NULL);
		it++;
	}

	CloseHandle(hFile);
		
	if (hLib) {
		FreeLibrary(hLib);
	}
		
	DebugMessage("生成Esig文件完毕！！！");
	m_block.clear();
	m_FuncOk.clear();
	m_call.clear();
}



/*
	8B 44 24 0C 50 E8 ?? ?? ?? ?? 83 C4 04 8B C8
	68 ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? C7 40 04 00 00 00 00 B9 ?? ?? ?? ??
	8B 44 24 0C 50 E8 ?? ?? ?? ?? 8B C8 83 C4 04 83 C1 5C
*/
	
void CCodMakeDlg::OnDropFiles(HDROP hDropInfo)
{
	WCHAR wcStr[MAX_PATH] = { 0 };
	CString	strFile;
	int DropCount = DragQueryFile(hDropInfo, -1, NULL, 0);//取得被拖动文件的数目  
	DragQueryFile(hDropInfo, 0, wcStr, MAX_PATH);//获得拖曳的第i个文件的文件名
	DragFinish(hDropInfo);  //拖放结束后,释放内存  
	MakeCode(wcStr);
	CDialog::OnDropFiles(hDropInfo);
}
