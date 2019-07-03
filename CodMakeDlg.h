
// CodMakeDlg.h : 头文件
//

#include "afxwin.h"
#include <vector>
#include <map>

using namespace std;
#define MAX_ESIZE 256
#define CALL_LEVEL 2    //遍历CALL的层数
// CCodMakeDlg 对话框
class CCodMakeDlg : public CDialog
{
// 构造
public:
	CCodMakeDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_CODMAKE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnDropFiles(HDROP hDropInfo);
	CListBox m_output;
	CStatic m_libname;

	void MakeCode(LPWSTR lpFile);

	void DebugMessage(char *format, ...);


	BOOL GenerateRelocationMap(unsigned char* pdll, ptrdiff_t delta);
	BOOL GenerateIATMap(unsigned char* pdll);

	INT Findprocend(ULONG FuncStartAddr,string& FuncText); //追朔函数过程,生成每个函数对应的文本形式

	
	
	map<ULONG, BOOL> m_relocation;
	map<ULONG, string> m_import;


	UINT CallLevel=0;



	map<ULONG, BOOL> m_block;

	map<string, string> m_FuncOk;  //保存函数,key为函数名称,value为函数文本
	map<string, BOOL> m_call;   //key为call的地址名称,value为call函数是否已经完成

	HANDLE	hFile;
	HMODULE	hLib;
	DWORD	dwWritten = 0;

	DWORD	SectionSize = 0;

	INT IsRelocated(ULONG addr,int len);
	CButton m_checksource;
};
