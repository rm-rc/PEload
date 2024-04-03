#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <AccCtrl.h>
#include <list>
#include <windef.h>
#include <Tlhelp32.h>
using namespace std;

//定义函数指针
typedef int(_stdcall* lpPlus)(int, int);

//声明函数指针变量
lpPlus myPus;

//插入第几个节
#define KONBCOUNT 2

//文件大小
DWORD g_FileLength;

IMAGE_DOS_HEADER image_Dos;				//Dos头
IMAGE_FILE_HEADER image_File;			//标准PE头
union
{
	IMAGE_OPTIONAL_HEADER32 image_Opeional32;
	IMAGE_OPTIONAL_HEADER64 image_Opeional64;
}image_Opeional;

//节表记录
std::list<IMAGE_SECTION_HEADER> list_Section;

char g_Data[] = { 0x6A, 0x04, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00 };
//Messagebox的地址
DWORD g_Address;

//所有表的数据
IMAGE_DATA_DIRECTORY g_DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

//打开EXE 将数据写入内存 返回数据指针
char* OpenFile_(const char* File);

//新打开文件
char* NewOpenFile(char* File, PDWORD pFileLength);

//获取PE结构数据
void GetPEData(char* FileBuff);

//将PE进行拉伸 返回拉伸后的指针
char* PEStretch(char* FileBuff);

//将拉伸后的数据 还原并存盘
void RestoreAndSave(char* ImageBuff, int Length = 0);

//Foa转RVA 
DWORD FoaToRva(int Foa);

DWORD RvaToFoa(int Rva);

//获取到MessageBoxA的地址
DWORD GetMessageboxAddress();

//在空白区域插入代码
void InsertCode(char* ImagerBuff);


//扩大一个节
void EnlargeLastKnob(char* ImageBuff, int Length);


//返回对齐后的大小  Size未对齐大小    align 需要对齐
DWORD GetAilgnmentSize(DWORD Size, DWORD align);


//新增一个节
DWORD AddKnob(char* ImageBuff, int Length);


//打印导出表
void ShowExport(char* FileBuff);

//给函数名 从中获取函数地址 （返回的是文件地址）
DWORD GetFileAddressFun(char* Filebuff, char* pfunName);

//给序号 获取函数地址
DWORD GetIDAddressFun(char* FileBuff, DWORD ID);

//打印重定位表
DWORD ShowRelocationTable(char* FileBuff);

//添加新节 返回新的filebuff
char* AddKonb(char* FileBuff, DWORD Length);

//移动导出表
void MoveExportTable(char* FileBuff, DWORD Length);

//移动重定位表
void MoveRelocationTable(char* FileBuff, DWORD Length);

//修改ImageBase  在对重定位表进行修复
void RepairRelocationTable(char* FileBuff, DWORD Length);

//打印导入表
void ShowImportTable(char* FileBuff);

//打印绑定导入表
void ShowBindingImportTable(char* FileBuff);

//加密
char* Encryption(char* FileBuff, DWORD dwLength);

//拷贝数据进最后一个节
void CopyData(char* FileBuff, char* FileEncrytion, DWORD dwLength);

//远程线程调用
void RemoteThreadHook(char* szPath, DWORD dwPID);

//SetWindowHookEx 拦截系统消息 并注入dll
bool SetWinHookInject(char* szDllPath, char* saProcessName);

//通过进程名获取线程ID
UINT32 GetTargetThreadIdFromProcessName(char* ProcessName);

//获取共享内存中的数据
void GetMappingBuffer();

//读取共享内存中的数据 （用进程通信的方式）
void ReadMappingBuffer();

//注册表读写
void regeditRead_Write();

//卷(磁盘) 相关操作
void Disk();

//目录相关操作
void FileStruct();

//文件相关操作
void TextFile();

typedef int(__stdcall* lpPlus)(int, int);
typedef int(__stdcall* lpSub)(int, int);
typedef int(__stdcall* lpMul)(int, int);
typedef int(__stdcall* lpDiv)(int, int);

int main()
{

	/*lpPlus plus;
	lpSub Sub;
	lpMul Mul;
	lpDiv Div;

	HINSTANCE hModule = LoadLibrary("c.dll");

	plus = (lpPlus)GetProcAddress(hModule, "Plus");
	Sub = (lpSub)GetProcAddress(hModule, (LPCSTR)0xf);
	Mul = (lpMul)GetProcAddress(hModule, "Mul");
	Div = (lpDiv)GetProcAddress(hModule, "Div");
	*/

	char* FileBuff = NULL;
	char* ImageBuff = NULL;
	// 	DWORD dwLength = 0;
	// 	//FileBuff = NewOpenFile("F:\\PETool 1.0.0.5.exe", &dwLength);
	FileBuff = OpenFile_("test.dll");
	GetPEData(FileBuff);
	//


	////------加密---------
	//char* FileEncrytion = Encryption(FileBuff,dwLength);

	////扩充一个节用来存放加密数据
	//FileBuff = OpenFile("F:\\PE解析\\decode\\Debug\\decode.exe");
	//GetPEData(FileBuff);
	//char* newFileBuff = AddKonb(FileBuff, dwLength);
	////将加密数据放入最后一个节中

	//CopyData(newFileBuff, FileEncrytion, dwLength);
	//


	//--------拉伸-------
	ImageBuff = PEStretch(FileBuff);
	//-----------------------
	AddKnob(ImageBuff, 0x2000);
	RestoreAndSave(ImageBuff);

	//在空白区域添加代码 -----
	//LoadLibraryA("f.dll");
	//GetMessageboxAddress();
	//InsertCode(ImageBuff);
	//---------------------------//

	//扩大最后一个节
	//EnlargeLastKnob(ImageBuff, 0x1000);

	//------打印导出表-------
	//ShowExport(FileBuff);
	//---------------------

	//------根据函数名获取函数地址------
	//文件地址
	//GetFileAddressFun(FileBuff, "DllCanUnloadNow");
	//GetIDAddressFun(FileBuff, 0x7fb);
	//------------------

	//--------打印重定位表-------------
	//ShowRelocationTable(FileBuff);
	//------------------

	//-------移动导出表和重定位表-----------
	//char* newFileBuff = AddKonb(FileBuff, 0x2000);
	//MoveExportTable(newFileBuff, 0x2000);
	//MoveRelocationTable(newFileBuff, 0x2000);
	//----------------------------------------

	//----------修复重定位表--------------
	//RepairRelocationTable(FileBuff, 0x10000000);
	//---------------------------

	//----------打印导入表------------
	//ShowImportTable(FileBuff);
	//-----------------------

	//----------打印绑定导入表---------
	//ShowBindingImportTable(FileBuff);
	//----------------------------

	//-----------获取窗口句柄--------
	//HWND hwnd = FindWindow("EMOAGUI", NULL);
	//RECT rect;
	//SetWindowText(hwnd, "大佬的有度");
	//ShowWindow(hwnd, SW_MAXIMIZE);
	////获取鼠标位置
	//GetWindowRect(hwnd, &rect);
	////设置鼠标位置
	//SetWindowPos(hwnd, HWND_BOTTOM, rect.left + 10, rect.right + 20,0,0 ,SWP_SHOWWINDOW);
	//Sleep(3000);
	////鼠标左键点击
	//mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
	//mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);


	//----------------------------远程线程调用---------------
	//DWORD dwID = 0;
	//HWND  hcalc = (HWND)0x000401F8;
	//DWORD dwPid = 0;
	//DWORD dwRub = GetWindowThreadProcessId(hcalc, &dwPid);


	//RemoteThreadHook("F:\\PE解析\\IatHook\\Debug\\IatHook.dll", 5984);

	//---------SetWindowHookEx-------------------------
	//SetWinHookInject("IatHook.dll","youdu.exe");
	//---------------------------------------------

	//--------------创建共享内存-----------------
	//GetMappingBuffer();
	//------------------------------------

	//---------------读取共享内存的数据 （进程通信方式）-----------
	//ReadMappingBuffer();


	//-------------注册表读写-------------
	//regeditRead_Write();
	//-----------------------

	//-------------磁盘 操作---------------	
	//Disk();
	//------------目录  操作------------------
	//FileStruct();
	//-------------文件 操作------------------
	//TextFile();


	return 0;
}


char* OpenFile_(const char* File)
{
	if (File == NULL)
	{
		return NULL;
	}
	char* fileBuff = NULL;
	FILE* file = fopen(File, "rb+");
	if (file)
	{
		fseek(file, 0L, SEEK_END); /* 定位到文件末尾 */
		g_FileLength = ftell(file);
		fileBuff = (char*)malloc(g_FileLength); /* 根据文件大小动态分配内存空间 */
		ZeroMemory(fileBuff, g_FileLength);
		if (fileBuff == NULL)
		{
			fclose(file);
			return 0;
		}
		fseek(file, 0L, SEEK_SET); /* 定位到文件开头 */
		fread(fileBuff, g_FileLength, 1, file); /* 一次性读取全部文件内容 */
		fclose(file);
		return fileBuff;
	}
	return NULL;

}

char* NewOpenFile(char* File, PDWORD pFileLength)
{
	if (File == NULL)
	{
		return NULL;
	}
	char* fileBuff = NULL;
	FILE* file = fopen(File, "rb+");
	if (file)
	{
		fseek(file, 0L, SEEK_END); /* 定位到文件末尾 */
		*pFileLength = ftell(file);
		fileBuff = (char*)malloc(*pFileLength); /* 根据文件大小动态分配内存空间 */
		ZeroMemory(fileBuff, *pFileLength);
		if (fileBuff == NULL)
		{
			fclose(file);
			return 0;
		}
		fseek(file, 0L, SEEK_SET); /* 定位到文件开头 */
		fread(fileBuff, *pFileLength, 1, file); /* 一次性读取全部文件内容 */
		fclose(file);
		return fileBuff;
	}
	return NULL;

}

void GetPEData(char* FileBuff)
{
	if (FileBuff == NULL)
	{
		return;
	}
	WORD MZ = (WORD)*FileBuff;
	if (MZ == 0x4D)
	{
		//对DOS头 标准PE头  可选PE头 进行拷贝
		memcpy(&image_Dos, FileBuff, sizeof(IMAGE_DOS_HEADER));
		memcpy(&image_File, FileBuff + 4 + image_Dos.e_lfanew, sizeof(IMAGE_FILE_HEADER));
		printf("32位%d   64位%d", sizeof(IMAGE_OPTIONAL_HEADER32), sizeof(IMAGE_OPTIONAL_HEADER64));
		if (image_File.SizeOfOptionalHeader == 0xE0)
		{
			memcpy(&image_Opeional.image_Opeional32, FileBuff + 4 + image_Dos.e_lfanew + sizeof(IMAGE_FILE_HEADER), image_File.SizeOfOptionalHeader);
			memcpy(g_DataDirectory, image_Opeional.image_Opeional32.DataDirectory, sizeof(g_DataDirectory));
		}
		else
		{
			memcpy(&image_Opeional.image_Opeional64, FileBuff + 4 + image_Dos.e_lfanew + sizeof(IMAGE_FILE_HEADER), image_File.SizeOfOptionalHeader);
			memcpy(g_DataDirectory, image_Opeional.image_Opeional64.DataDirectory, sizeof(g_DataDirectory));
		}
		//获取一下从DOS头到可选PE头的指针  头指针 + DOS头偏移 + 标准PE大小 + 可选PE大小
		char* opFile = FileBuff + 4 + image_Dos.e_lfanew + sizeof(IMAGE_FILE_HEADER) + image_File.SizeOfOptionalHeader;
		//节表保存
		for (size_t i = 0; i < image_File.NumberOfSections; i++)
		{
			IMAGE_SECTION_HEADER section = { 0 };
			memcpy(&section, opFile, sizeof(IMAGE_SECTION_HEADER));
			list_Section.push_back(section);
			opFile += sizeof(IMAGE_SECTION_HEADER);
		}
		//获取所有目录表项
	}
}

char* PEStretch(char* FileBuff)
{
	if (!FileBuff)
	{
		return NULL;
	}
	char* ImageBuff = NULL;
	//第一步申请拉伸后的内存大小
	if (image_File.SizeOfOptionalHeader == 0xE0)
	{
		ImageBuff = (char*)malloc(image_Opeional.image_Opeional32.SizeOfImage);
		if (!ImageBuff)
		{
			printf("malloc申请失败");
			return NULL;
		}
		ZeroMemory(ImageBuff, image_Opeional.image_Opeional32.SizeOfImage);

		//将所有头加节对齐后的大小拷贝进 imageBuff
		memcpy(ImageBuff, FileBuff, image_Opeional.image_Opeional32.SizeOfHeaders);

		std::list<IMAGE_SECTION_HEADER>::iterator it = list_Section.begin();
		//将节一个一个放进去
		for (size_t i = 0; i < image_File.NumberOfSections; i++)
		{
			//问题 it->Misc.VirtualSize 这个值很可能是内存对齐后的大小
			memcpy(ImageBuff + it->VirtualAddress, FileBuff + it->PointerToRawData, it->SizeOfRawData);
			it++;
		}
		return ImageBuff;
	}
	else
	{
		ImageBuff = (char*)malloc(image_Opeional.image_Opeional64.SizeOfImage);
		if (!ImageBuff)
		{
			printf("malloc申请失败");
			return NULL;
		}
		ZeroMemory(ImageBuff, image_Opeional.image_Opeional64.SizeOfImage);

		//将所有头加节对齐后的大小拷贝进 imageBuff
		memcpy(ImageBuff, FileBuff, image_Opeional.image_Opeional64.SizeOfHeaders);

		std::list<IMAGE_SECTION_HEADER>::iterator it = list_Section.begin();
		//将节一个一个放进去
		for (size_t i = 0; i < image_File.NumberOfSections; i++)
		{
			//问题 it->Misc.VirtualSize 这个值很可能是内存对齐后的大小
			memcpy(ImageBuff + it->VirtualAddress, FileBuff + it->PointerToRawData, it->SizeOfRawData);
			it++;
		}
		return ImageBuff;
	}
}

DWORD FoaToRva(int Foa)
{
	DWORD Rva = 0;
	for (auto it : list_Section)
	{
		if (it.Misc.VirtualSize > it.SizeOfRawData)
		{
			if (it.PointerToRawData == 0)
			{
				continue;
			}
			if (it.PointerToRawData <= Foa && Foa < (it.Misc.VirtualSize + it.PointerToRawData))
			{
				Rva = Foa - it.PointerToRawData;
				return it.VirtualAddress + Rva;
			}
		}
		else
		{
			if (it.PointerToRawData <= Foa && Foa < (it.PointerToRawData + it.SizeOfRawData))
			{
				Rva = Foa - it.PointerToRawData;
				return it.VirtualAddress + Rva;
			}
		}
	}
}

DWORD RvaToFoa(int Rva)
{
	DWORD Foa = 0;
	for (auto it : list_Section)
	{
		if (it.Misc.VirtualSize > it.SizeOfRawData)
		{
			if (it.VirtualAddress <= Rva && Rva <= (it.Misc.VirtualSize + it.VirtualAddress))
			{
				Foa = Rva - it.VirtualAddress;
				return  it.PointerToRawData + Foa;
			}
		}
		else
		{
			if (it.VirtualAddress <= Rva && Rva <= (it.VirtualAddress + it.SizeOfRawData))
			{
				Foa = Rva - it.VirtualAddress;
				return  it.PointerToRawData + Foa;
			}
		}
	}
}

void RestoreAndSave(char* ImageBuff, int Length)
{
	if (ImageBuff == NULL)
	{
		return;
	}
	if (Length == 0)
	{
		Length = g_FileLength;
	}
	else
	{
		Length += g_FileLength;
	}
	char* FileBuff = (char*)malloc(Length);
	if (FileBuff == NULL)
	{
		return;
	}
	ZeroMemory(FileBuff, Length);

	//先将所有头+节表一次性拷贝过去 
	memcpy(FileBuff, ImageBuff, image_Opeional.image_Opeional32.SizeOfHeaders);

	//将每个节拷贝进去
	std::list<IMAGE_SECTION_HEADER>::iterator it = list_Section.begin();
	//将节一个一个放进去
	for (size_t i = 0; i < image_File.NumberOfSections; i++)
	{
		if (it == list_Section.end())
		{
			break;
		}
		//if (it->Misc.VirtualSize > it->SizeOfRawData)
		//{
		//	memcpy(FileBuff + it->PointerToRawData, ImageBuff + it->VirtualAddress, it->Misc.VirtualSize);
		//}
		//else
		//{
		//	memcpy(FileBuff + it->PointerToRawData, ImageBuff + it->VirtualAddress, it->SizeOfRawData);
		//}
		memcpy(FileBuff + it->PointerToRawData, ImageBuff + it->VirtualAddress, it->SizeOfRawData);
		it++;
	}

	//生成一个新文件 并将PE拷贝进新文件中
	FILE* file = fopen("a.exe", "wb+");
	fwrite(FileBuff, 1, Length, file);
	fclose(file);
	delete FileBuff;

}


//获取MessageBox地址
DWORD GetMessageboxAddress()
{
	//HANDLE handle = NULL;
	HMODULE hmodule = NULL;
	//获取程序句柄
	//handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
	//if (handle == NULL)
	//{
	//	printf("获取句柄失败");
	//	return 0;
	//}
	//获取模块地址
	hmodule = GetModuleHandleA("f.dll");
	DWORD a = GetLastError();
	if (hmodule == NULL)
	{
		printf("获取模块失败");
		return 0;
	}
	//0x771cff46                        
	myPus = (lpPlus)GetProcAddress(hmodule, "Pus");
	//CloseHandle(hmodule);
}


void InsertCode(char* ImagerBuff)
{
	if (ImagerBuff == NULL)
	{
		return;
	}
	std::list<IMAGE_SECTION_HEADER>::iterator it = list_Section.begin();
	for (size_t i = 0; i < image_File.NumberOfSections; i++)
	{
		if (it == list_Section.end())
		{
			break;
		}
		if (it->SizeOfRawData - (it->VirtualAddress + it->Misc.VirtualSize) > sizeof(g_Data))
		{
			DWORD  address = it->VirtualAddress + it->Misc.VirtualSize;
			memcpy(ImagerBuff + address, &g_Data, sizeof(g_Data));
			//算E8跳转
			DWORD  table = g_Address - (image_Opeional.image_Opeional32.ImageBase + address + 0x0E);
			memcpy(ImagerBuff + address + 0x09, &table, sizeof(DWORD));

			DWORD byte1 = (image_Opeional.image_Opeional32.ImageBase + address + 0x16) - (image_Opeional.image_Opeional32.ImageBase + address + 0x13);
			memcpy(ImagerBuff + address + 0x10, &byte1, sizeof(DWORD));

			//算E9跳转
			DWORD  table2 = (image_Opeional.image_Opeional32.ImageBase + image_Opeional.image_Opeional32.AddressOfEntryPoint) - (image_Opeional.image_Opeional32.ImageBase + address + 0x1B);
			memcpy(ImagerBuff + address + 0x15, &table2, sizeof(DWORD));



			image_Opeional.image_Opeional32.AddressOfEntryPoint = address;
			memcpy(ImagerBuff + 4 + image_Dos.e_lfanew + sizeof(IMAGE_FILE_HEADER), &image_Opeional.image_Opeional32, image_File.SizeOfOptionalHeader);
			break;
		}
		it++;
	}
	RestoreAndSave(ImagerBuff);
}

void EnlargeLastKnob(char* ImageBuff, int Length)
{
	if (ImageBuff == NULL)
	{
		return;
	}

	image_Opeional.image_Opeional32.SizeOfImage += Length;
	if (image_File.SizeOfOptionalHeader == 0xE0)
	{
		memcpy(ImageBuff + image_Dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), &image_Opeional.image_Opeional32, image_File.SizeOfOptionalHeader);
	}
	else
	{
		memcpy(ImageBuff + image_Dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), &image_Opeional.image_Opeional64, image_File.SizeOfOptionalHeader);
	}

	char* opImage = ImageBuff + 4 + image_Dos.e_lfanew + sizeof(IMAGE_FILE_HEADER) + image_File.SizeOfOptionalHeader;

	std::list<IMAGE_SECTION_HEADER>::iterator it = list_Section.begin();
	for (size_t i = 0; i < image_File.NumberOfSections; i++)
	{
		if (it == list_Section.end())
		{
			break;
		}
		if ((i + 1) == image_File.NumberOfSections)
		{
			if (it->Misc.VirtualSize > it->SizeOfRawData)
			{
				it->SizeOfRawData = it->Misc.VirtualSize += Length;
			}
			else
			{
				it->Misc.VirtualSize = it->SizeOfRawData += Length;
			}
			memcpy(opImage, &(*it), sizeof(IMAGE_SECTION_HEADER));
		}
		it++;
		opImage += sizeof(IMAGE_SECTION_HEADER);
	}

	RestoreAndSave(ImageBuff, Length);

}

DWORD AddKnob(char* ImageBuff, int Length)
{
	if (ImageBuff == NULL)
	{
		return 0;
	}
	//新增节表数
	image_File.NumberOfSections += 1;
	memcpy(ImageBuff + image_Dos.e_lfanew + 4, &image_File, sizeof(IMAGE_FILE_HEADER));
	//先修改内存大小
	image_Opeional.image_Opeional32.SizeOfImage += Length;
	if (image_File.SizeOfOptionalHeader == 0xE0)
	{
		memcpy(ImageBuff + image_Dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), &image_Opeional.image_Opeional32, image_File.SizeOfOptionalHeader);
	}
	else
	{
		memcpy(ImageBuff + image_Dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), &image_Opeional.image_Opeional64, image_File.SizeOfOptionalHeader);
	}

	//在新增一个节
	std::list<IMAGE_SECTION_HEADER>::iterator it = prev(list_Section.end());

	IMAGE_SECTION_HEADER section = { 0 };
	memcpy(section.Name, "rrrr.", sizeof(section.Name));
	section.Misc.VirtualSize = Length;
	if (it->Misc.VirtualSize > it->SizeOfRawData)
	{
		section.VirtualAddress = GetAilgnmentSize(it->VirtualAddress + it->Misc.VirtualSize, image_Opeional.image_Opeional32.SectionAlignment);
		section.PointerToRawData = GetAilgnmentSize(it->PointerToRawData + it->Misc.VirtualSize, image_Opeional.image_Opeional32.FileAlignment);
	}
	else
	{
		section.VirtualAddress = GetAilgnmentSize(it->VirtualAddress + it->SizeOfRawData, image_Opeional.image_Opeional32.SectionAlignment);
		section.PointerToRawData = GetAilgnmentSize(it->PointerToRawData + it->SizeOfRawData, image_Opeional.image_Opeional32.FileAlignment);

	}
	section.SizeOfRawData = Length;
	section.Characteristics = 0x88508880;
	section.PointerToRelocations = it->PointerToRelocations;
	section.PointerToLinenumbers = it->PointerToLinenumbers;
	section.NumberOfRelocations = it->NumberOfRelocations;
	section.NumberOfLinenumbers = it->NumberOfLinenumbers;

	list_Section.insert(it, section);


	return 0;
}


void ShowExport(char* FileBuff)
{
	if (FileBuff == NULL)
	{
		return;
	}

	if (g_DataDirectory->VirtualAddress == 0)
	{
		printf("该文件没有导出表");
		return;
	}
	IMAGE_EXPORT_DIRECTORY Image_export = { 0 };

	DWORD ExportAddress = RvaToFoa(g_DataDirectory->VirtualAddress);

	memcpy(&Image_export, FileBuff + ExportAddress, sizeof(Image_export));

	DWORD table = RvaToFoa(Image_export.Name);

	printf("\n当前DLL为：%s \n", FileBuff + table);

	printf("---------函数地址--------------\n");
	DWORD Table1 = RvaToFoa(Image_export.AddressOfFunctions);
	for (size_t i = 0; i < Image_export.NumberOfFunctions; i++)
	{
		DWORD FunAddress = 0;
		memcpy(&FunAddress, FileBuff + Table1, sizeof(DWORD));
		printf("地址为：%x\n", FunAddress);
		Table1 += sizeof(DWORD);
	}

	printf("--------函数名------------------\n");
	DWORD table2 = RvaToFoa(Image_export.AddressOfNames);
	for (size_t i = 0; i < Image_export.NumberOfNames; i++)
	{
		DWORD funName = 0;
		memcpy(&funName, FileBuff + table2, sizeof(DWORD));
		DWORD funNameAddress = RvaToFoa(funName);
		printf("函数名：%s\n", FileBuff + funNameAddress);
		table2 += sizeof(DWORD);
	}

	printf("-----------导出序号----------------\n");
	DWORD table3 = RvaToFoa(Image_export.AddressOfNameOrdinals);
	for (size_t i = 0; i < Image_export.NumberOfNames; i++)
	{
		WORD ID = 0;
		memcpy(&ID, FileBuff + table3, sizeof(WORD));
		printf("序号：%d\n", ID);
		table3 += sizeof(WORD);
	}
}

DWORD GetFileAddressFun(char* Filebuff, char* pfunName)
{
	if (Filebuff == NULL)
	{
		return 0;
	}
	if (g_DataDirectory->VirtualAddress == 0)
	{
		printf("该文件没有导出表");
		return 0;
	}
	IMAGE_EXPORT_DIRECTORY Image_export = { 0 };

	DWORD ExportAddress = RvaToFoa(g_DataDirectory->VirtualAddress);

	memcpy(&Image_export, Filebuff + ExportAddress, sizeof(Image_export));

	printf("--------函数名------------------\n");
	DWORD table2 = RvaToFoa(Image_export.AddressOfNames);
	for (size_t i = 0; i < Image_export.NumberOfNames; i++)
	{
		DWORD funName = 0;
		memcpy(&funName, Filebuff + table2, sizeof(DWORD));
		DWORD funNameAddress = RvaToFoa(funName);

		if (strcmp(pfunName, Filebuff + funNameAddress) == 0)
		{
			printf("函数名：%s\n", Filebuff + funNameAddress);
			printf("-----------导出序号----------------\n");
			DWORD table3 = RvaToFoa(Image_export.AddressOfNameOrdinals);
			for (size_t j = 0; j < Image_export.NumberOfFunctions; j++)
			{
				WORD ID = 0;
				if (j == i)
				{
					memcpy(&ID, Filebuff + table3, sizeof(WORD));
					printf("---------函数地址--------------\n");
					DWORD Table1 = RvaToFoa(Image_export.AddressOfFunctions);
					for (size_t k = 0; k < Image_export.NumberOfFunctions; k++)
					{
						DWORD FunAddress = 0;
						if (ID == k)
						{
							memcpy(&FunAddress, Filebuff + Table1, sizeof(DWORD));
							printf("地址为：%x\n", FunAddress);
						}
						Table1 += sizeof(DWORD);
					}
				}
				table3 += sizeof(WORD);
			}
		}
		table2 += sizeof(DWORD);
	}
}

DWORD GetIDAddressFun(char* FileBuff, DWORD ID)
{
	if (FileBuff == NULL)
	{
		return 0;
	}

	if (g_DataDirectory->VirtualAddress == 0)
	{
		printf("该文件没有导出表");
		return 0;
	}
	IMAGE_EXPORT_DIRECTORY Image_export = { 0 };

	DWORD ExportAddress = RvaToFoa(g_DataDirectory->VirtualAddress);

	memcpy(&Image_export, FileBuff + ExportAddress, sizeof(Image_export));

	DWORD address = ID - Image_export.Base;

	printf("---------函数地址--------------\n");
	DWORD Table1 = RvaToFoa(Image_export.AddressOfFunctions);
	for (size_t k = 0; k < Image_export.NumberOfFunctions; k++)
	{
		DWORD FunAddress = 0;
		if (address == k)
		{
			memcpy(&FunAddress, FileBuff + Table1, sizeof(DWORD));
			printf("地址为：%x\n", FunAddress);
		}
		Table1 += sizeof(DWORD);
	}
}

DWORD ShowRelocationTable(char* FileBuff)
{
	if (FileBuff == NULL)
	{
		return 0;
	}
	if (g_DataDirectory[5].VirtualAddress == 0)
	{
		printf("该文件没有重定位表");
		return 0;
	}
	IMAGE_BASE_RELOCATION Image_relocation = { 0 };

	DWORD relocationAddress = RvaToFoa(g_DataDirectory[5].VirtualAddress);

	memcpy(&Image_relocation, FileBuff + relocationAddress, sizeof(IMAGE_BASE_RELOCATION));

	//获取重定位表的起始点
	char* RelocationBuff = FileBuff + relocationAddress;
	while (Image_relocation.VirtualAddress != 0 && Image_relocation.SizeOfBlock != 0)
	{
		char* table = RelocationBuff + sizeof(IMAGE_BASE_RELOCATION);
		DWORD RelocationSize = (Image_relocation.SizeOfBlock - 8) / 2;
		for (size_t i = 0; i < RelocationSize; i++)
		{
			//获取第一个偏移的指针
			WORD offset = *(PWORD)table;
			if ((offset & 0x3000) == 0x3000)
			{
				//DWORD ActualOffset = *(PDWORD)FileBuff + RvaToFoa(Image_relocation.VirtualAddress + offset);
				printf("\n需要修改地址：%x", offset);
			}
			table += sizeof(WORD);
		}
		RelocationBuff += Image_relocation.SizeOfBlock;
		memcpy(&Image_relocation, RelocationBuff, sizeof(IMAGE_BASE_RELOCATION));
	}

}



char* AddKonb(char* FileBuff, DWORD Length)
{
	if (FileBuff == NULL)
	{
		return NULL;
	}

	std::list<IMAGE_SECTION_HEADER>::iterator it = --list_Section.end();

	IMAGE_SECTION_HEADER section = { 0 };
	memcpy(section.Name, "rrrr.", sizeof(section.Name));
	section.Misc.VirtualSize = GetAilgnmentSize(Length, image_Opeional.image_Opeional32.FileAlignment);
	if (it->Misc.VirtualSize > it->SizeOfRawData)
	{
		section.VirtualAddress = GetAilgnmentSize(it->VirtualAddress + it->Misc.VirtualSize, image_Opeional.image_Opeional32.SectionAlignment);
		section.PointerToRawData = GetAilgnmentSize(it->PointerToRawData + it->Misc.VirtualSize, image_Opeional.image_Opeional32.FileAlignment);
	}
	else
	{
		section.VirtualAddress = GetAilgnmentSize(it->VirtualAddress + it->SizeOfRawData, image_Opeional.image_Opeional32.SectionAlignment);
		section.PointerToRawData = GetAilgnmentSize(it->PointerToRawData + it->SizeOfRawData, image_Opeional.image_Opeional32.FileAlignment);

	}
	section.SizeOfRawData = GetAilgnmentSize(Length, image_Opeional.image_Opeional32.FileAlignment);
	section.Characteristics = 0x88508880;
	section.PointerToRelocations = it->PointerToRelocations;
	section.PointerToLinenumbers = it->PointerToLinenumbers;
	section.NumberOfRelocations = it->NumberOfRelocations;
	section.NumberOfLinenumbers = it->NumberOfLinenumbers;

	list_Section.push_back(section);

	//获取最后节表的位置
	char* KontSize = FileBuff + image_Dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + image_File.SizeOfOptionalHeader;
	KontSize += sizeof(IMAGE_SECTION_HEADER) * image_File.NumberOfSections;
	it = list_Section.begin();
	DWORD dwSize = (DWORD)(FileBuff + it->PointerToRawData) - (DWORD)KontSize;
	if (dwSize > 0x80)
	{
		IMAGE_SECTION_HEADER sectionTabel = { 0 };
		memcpy(KontSize, &section, sizeof(IMAGE_SECTION_HEADER));
		KontSize += sizeof(IMAGE_SECTION_HEADER);
		memcpy(KontSize, &sectionTabel, sizeof(IMAGE_SECTION_HEADER));


		//修改节表数
		image_File.NumberOfSections += 1;
		memcpy(FileBuff + image_Dos.e_lfanew + 4, &image_File, sizeof(IMAGE_FILE_HEADER));

		//修改内存大小
		image_Opeional.image_Opeional32.SizeOfImage += Length;
		image_Opeional.image_Opeional32.SizeOfImage = GetAilgnmentSize(image_Opeional.image_Opeional32.SizeOfImage, image_Opeional.image_Opeional32.SectionAlignment);
		memcpy(FileBuff + image_Dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), &image_Opeional, image_File.SizeOfOptionalHeader);


		//申请内存
		char* newFileBuff = (char*)malloc(g_FileLength + Length);
		if (newFileBuff == NULL)
		{
			return NULL;
		}
		ZeroMemory(newFileBuff, g_FileLength + Length);

		//先将所有头+节表一次性拷贝过去 
		memcpy(newFileBuff, FileBuff, image_Opeional.image_Opeional32.SizeOfHeaders);

		//将每个节拷贝进去
		std::list<IMAGE_SECTION_HEADER>::iterator itsection = list_Section.begin();
		//将节一个一个放进去
		for (size_t i = 0; i < image_File.NumberOfSections - 1; i++)
		{
			if (itsection == list_Section.end())
			{
				break;
			}
			memcpy(newFileBuff + itsection->PointerToRawData, FileBuff + itsection->PointerToRawData, itsection->SizeOfRawData);
			itsection++;
		}
		return newFileBuff;

	}
	else
	{
		return nullptr;
	}

}

void MoveExportTable(char* FileBuff, DWORD Length)
{
	if (FileBuff == nullptr)
	{
		return;
	}
	if (g_DataDirectory->VirtualAddress == 0)
	{
		printf("该文件没有导出表");
		return;
	}
	IMAGE_EXPORT_DIRECTORY Image_export = { 0 };
	DWORD ExportAddress = RvaToFoa(g_DataDirectory->VirtualAddress);
	memcpy(&Image_export, FileBuff + ExportAddress, sizeof(Image_export));

	//实时记录转移到新节中的地址
	char* pMoveFile = NULL;
	//时刻使用的临时变量
	DWORD Rva = 0;
	//记录当前长度
	DWORD dwLength = 0;

	std::list<IMAGE_SECTION_HEADER>::iterator it = --list_Section.end();

	//将函数地址转移新的节
	DWORD Table1 = RvaToFoa(Image_export.AddressOfFunctions);
	memcpy(FileBuff + it->PointerToRawData, FileBuff + Table1, Image_export.NumberOfFunctions * sizeof(DWORD));
	//记录下当前指针位置
	pMoveFile = (FileBuff + it->PointerToRawData) + Image_export.NumberOfFunctions * sizeof(DWORD);
	//修改下偏移
	Rva = FoaToRva(it->PointerToRawData);
	Image_export.AddressOfFunctions = Rva;
	dwLength += it->PointerToRawData;

	//将序号表移动到新的节
	DWORD Table2 = RvaToFoa(Image_export.AddressOfNameOrdinals);
	memcpy(pMoveFile, FileBuff + Table2, Image_export.NumberOfNames * sizeof(WORD));
	//记录下当前指针位置
	pMoveFile = pMoveFile + (Image_export.NumberOfNames * sizeof(WORD));
	//修改下偏移
	dwLength += Image_export.NumberOfFunctions * sizeof(DWORD);
	Rva = FoaToRva(dwLength);
	Image_export.AddressOfNameOrdinals = Rva;



	//将函数名表移动到新的节
	//先移动函数名的地址RVA
	dwLength += Image_export.NumberOfNames * sizeof(WORD);
	DWORD table3 = RvaToFoa(Image_export.AddressOfNames);
	//然后来移动函数名
	for (size_t i = 0; i < Image_export.NumberOfNames; i++)
	{
		DWORD funName = 0;
		memcpy(&funName, FileBuff + table3, sizeof(DWORD));
		DWORD funNameAddress = RvaToFoa(funName);
		memcpy(pMoveFile, FileBuff + funNameAddress, strlen(FileBuff + funNameAddress));

		pMoveFile += strlen(FileBuff + funNameAddress) + 1;

		Rva = FoaToRva(dwLength);
		memcpy(FileBuff + table3, &Rva, sizeof(DWORD));

		dwLength += strlen(FileBuff + funNameAddress) + 1;
		table3 += sizeof(DWORD);
	}

	DWORD table4 = RvaToFoa(Image_export.AddressOfNames);
	memcpy(pMoveFile, FileBuff + table4, Image_export.NumberOfNames * sizeof(DWORD));
	//修改下当前指针位置
	pMoveFile = pMoveFile + (Image_export.NumberOfNames * sizeof(DWORD));
	//修改偏移
	Rva = FoaToRva(dwLength);
	Image_export.AddressOfNames = Rva;
	dwLength += (Image_export.NumberOfNames * sizeof(DWORD));

	//移动导出表结构
	memcpy(pMoveFile, &Image_export, sizeof(IMAGE_EXPORT_DIRECTORY));
	//修改偏移
	g_DataDirectory->VirtualAddress = FoaToRva(dwLength);
	memcpy(image_Opeional.image_Opeional32.DataDirectory, g_DataDirectory, sizeof(g_DataDirectory));
	memcpy(FileBuff + image_Dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), &image_Opeional.image_Opeional32, image_File.SizeOfOptionalHeader);

	FILE* file = fopen("c.dll", "wb+");
	fwrite(FileBuff, 1, g_FileLength + Length, file);
	fclose(file);
	delete FileBuff;
}


void MoveRelocationTable(char* FileBuff, DWORD Length)
{
	if (FileBuff == NULL)
	{
		return;
	}
	if (g_DataDirectory[5].VirtualAddress == 0)
	{
		printf("该文件没有重定位表");
		return;
	}
	IMAGE_BASE_RELOCATION Image_relocation = { 0 };

	DWORD relocationAddress = RvaToFoa(g_DataDirectory[5].VirtualAddress);

	memcpy(&Image_relocation, FileBuff + relocationAddress, sizeof(IMAGE_BASE_RELOCATION));

	//实时记录转移到新节中的地址
	char* pMoveFile = NULL;
	//时刻使用的临时变量
	DWORD Rva = 0;
	//记录当前长度
	DWORD dwLength = 0;


	std::list<IMAGE_SECTION_HEADER>::iterator it = --list_Section.end();
	pMoveFile = FileBuff + relocationAddress;
	dwLength += it->PointerToRawData;
	//将第一个重定位块 拷贝到新的节中
	while (Image_relocation.VirtualAddress != 0 && Image_relocation.SizeOfBlock != 0)
	{
		memcpy(FileBuff + dwLength, pMoveFile, Image_relocation.SizeOfBlock);
		//记录下当前指针位置
		pMoveFile += Image_relocation.SizeOfBlock;
		dwLength += Image_relocation.SizeOfBlock;
		memcpy(&Image_relocation, pMoveFile, sizeof(IMAGE_BASE_RELOCATION));
	}
	//修改下偏移
	Rva = FoaToRva(it->PointerToRawData);

	image_Opeional.image_Opeional32.DataDirectory[5].VirtualAddress = Rva;
	memcpy(FileBuff + image_Dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), &image_Opeional.image_Opeional32, image_File.SizeOfOptionalHeader);

	FILE* file = fopen("e.dll", "wb+");
	fwrite(FileBuff, 1, g_FileLength + Length, file);
	fclose(file);
	delete FileBuff;
}


void RepairRelocationTable(char* FileBuff, DWORD Length)
{
	if (FileBuff == NULL)
	{
		return;
	}
	if (g_DataDirectory[5].VirtualAddress == 0)
	{
		printf("该文件没有重定位表");
		return;
	}

	//先修改 ImageBase
	image_Opeional.image_Opeional32.ImageBase += Length;

	memcpy(FileBuff + image_Dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), &image_Opeional.image_Opeional32, image_File.SizeOfOptionalHeader);

	//开始修复重定位表
	IMAGE_BASE_RELOCATION Image_relocation = { 0 };

	DWORD relocationAddress = RvaToFoa(g_DataDirectory[5].VirtualAddress);

	memcpy(&Image_relocation, FileBuff + relocationAddress, sizeof(IMAGE_BASE_RELOCATION));

	char* RelocationBuff = FileBuff + relocationAddress;
	while (Image_relocation.VirtualAddress != 0 && Image_relocation.SizeOfBlock != 0)
	{
		char* table = RelocationBuff + sizeof(IMAGE_BASE_RELOCATION);
		DWORD RelocationSize = (Image_relocation.SizeOfBlock - 8) / 2;
		for (size_t i = 0; i < RelocationSize; i++)
		{
			//获取第一个偏移的指针
			WORD offset = *(PWORD)table;
			if ((offset & 0x3000) == 0x3000)
			{
				offset ^= 0x3000;
				DWORD foa = RvaToFoa(Image_relocation.VirtualAddress + offset);
				DWORD ActualOffset = *(PDWORD)(FileBuff + foa);
				ActualOffset += Length;
				memcpy(FileBuff + foa, &ActualOffset, sizeof(DWORD));
			}
			table += sizeof(WORD);
		}
		RelocationBuff += Image_relocation.SizeOfBlock;
		memcpy(&Image_relocation, RelocationBuff, sizeof(IMAGE_BASE_RELOCATION));
	}
	FILE* file = fopen("f.dll", "wb+");
	fwrite(FileBuff, 1, g_FileLength, file);
	fclose(file);
	delete FileBuff;
}

void ShowImportTable(char* FileBuff)
{
	if (FileBuff == NULL)
	{
		return;
	}
	if (g_DataDirectory[1].VirtualAddress == 0)
	{
		printf("该文件没有导入表");
		return;
	}

	IMAGE_IMPORT_DESCRIPTOR DataImport = { 0 };
	IMAGE_THUNK_DATA thunk = { 0 };

	DWORD Foa = RvaToFoa(g_DataDirectory[1].VirtualAddress);
	memcpy(&DataImport, FileBuff + Foa, sizeof(IMAGE_IMPORT_DESCRIPTOR));

	//存放导入表起始指针
	char* pImport = FileBuff + Foa;
	//存放INT的起始指针
	char* pInt = nullptr;
	//存放IAT的起始指针
	char* pIat = nullptr;


	while (DataImport.FirstThunk != 0 && DataImport.Name != 0 && DataImport.OriginalFirstThunk != 0)
	{
		Foa = RvaToFoa(DataImport.Name);
		printf("\n导入DLL名:%s\n", FileBuff + Foa);

		Foa = RvaToFoa(DataImport.OriginalFirstThunk);
		memcpy(&thunk, FileBuff + Foa, sizeof(IMAGE_THUNK_DATA));
		pInt = FileBuff + Foa;
		printf("-------------INT--------------------\n");
		printf("起始地址：%x\n", DataImport.OriginalFirstThunk);
		while (thunk.u1.AddressOfData != 0)
		{
			if ((thunk.u1.AddressOfData & 0x80000000) == 0x80000000)
			{
				printf("当前序号为：%x\n", thunk.u1.AddressOfData ^ 0x80000000);
			}
			else
			{
				Foa = RvaToFoa(thunk.u1.AddressOfData);
				printf("导入函数名称为：%s\n", FileBuff + Foa + sizeof(WORD));
			}
			if (image_File.SizeOfOptionalHeader == 0xE0)
			{
				pInt += sizeof(IMAGE_THUNK_DATA);
			}
			else
			{
				pInt += 8;
			}
			memcpy(&thunk, pInt, sizeof(IMAGE_THUNK_DATA));
		}

		Foa = RvaToFoa(DataImport.FirstThunk);
		memcpy(&thunk, FileBuff + Foa, sizeof(IMAGE_THUNK_DATA));
		pIat = FileBuff + Foa;
		printf("-------------INT--------------------\n");
		printf("起始地址：%x\n", DataImport.FirstThunk);
		while (thunk.u1.AddressOfData != 0)
		{
			if ((thunk.u1.AddressOfData & 0x80000000) == 0x80000000)
			{
				printf("当前序号为：%x\n", thunk.u1.AddressOfData ^ 0x80000000);
			}
			else if (DataImport.TimeDateStamp != 0)
			{
				printf("地址为：%x\n", thunk.u1.AddressOfData);
			}
			else
			{
				Foa = RvaToFoa(thunk.u1.AddressOfData);
				printf("导入函数名称为：%s\n", FileBuff + Foa + sizeof(WORD));
			}
			if (image_File.SizeOfOptionalHeader == 0xE0)
			{
				pIat += sizeof(IMAGE_THUNK_DATA);
			}
			else
			{
				pIat += 8;
			}
			memcpy(&thunk, pIat, sizeof(IMAGE_THUNK_DATA));
		}


		pImport += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		memcpy(&DataImport, pImport, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}

}

void ShowBindingImportTable(char* FileBuff)
{
	if (FileBuff == NULL)
	{
		return;
	}
	if (g_DataDirectory[12].VirtualAddress == 0)
	{
		printf("该文件没有绑定导入表");
		return;
	}

	IMAGE_BOUND_IMPORT_DESCRIPTOR Bound_Import = { 0 };

	DWORD Foa = RvaToFoa(g_DataDirectory[12].VirtualAddress);
	memcpy(&Bound_Import, FileBuff + Foa, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	Foa = RvaToFoa(*(PWORD)(FileBuff + Foa + Bound_Import.OffsetModuleName));


}


char* Encryption(char* FileBuff, DWORD dwLength)
{
	if (FileBuff == NULL)
	{
		return NULL;
	}
	char* NewFileBuff = FileBuff;
	for (DWORD i = 0; i < dwLength; i++)
	{
		BYTE Date = ~(*(PBYTE)NewFileBuff);
		*NewFileBuff = Date;
		NewFileBuff++;
	}

	return FileBuff;
}

void CopyData(char* FileBuff, char* FileEncrytion, DWORD dwLength)
{
	if (FileBuff == NULL || FileEncrytion == NULL)
	{
		return;
	}

	std::list<IMAGE_SECTION_HEADER>::iterator it = --list_Section.end();

	memcpy(FileBuff + it->PointerToRawData, FileEncrytion, dwLength);

	FILE* file = fopen("decode.exe", "wb+");
	fwrite(FileBuff, 1, g_FileLength + dwLength, file);
	fclose(file);
	delete FileBuff;

}

void RemoteThreadHook(char* szPath, DWORD dwPID)
{
	int a = 0;
	HANDLE hProess = ::OpenProcess(PROCESS_ALL_ACCESS, false, dwPID);
	a = ::GetLastError();
	if (!hProess)
	{
		return;
	}
	//申请空间
	LPVOID pRemoteAddress = VirtualAllocEx(hProess, NULL, 1, MEM_COMMIT, PAGE_READWRITE);

	a = GetLastError();
	//写入DLL路径
	DWORD dwWriteSize = 0;
	//写一段数据到指定进程所开辟的内存空间
	WriteProcessMemory(hProess, pRemoteAddress, szPath, strlen(szPath) * 2 + 2, &dwWriteSize);
	a = GetLastError();
	//创建远程线程,让目标进程调用LoadLibrary
	HANDLE hThead = CreateRemoteThread(hProess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, pRemoteAddress, NULL, NULL);
	a = GetLastError();
	WaitForSingleObject(hThead, -1);
	a = GetLastError();
	//释放申请的虚拟内存空间
	VirtualFreeEx(hProess, pRemoteAddress, 1, MEM_DECOMMIT);
	a = GetLastError();

}

bool SetWinHookInject(char* szDllPath, char* szProcessName)
{
	HMODULE ModuleHandle = NULL;
	bool bok = false;
	DWORD FunctionAddress = NULL;
	UINT32 dwThreadId = 0;
	HHOOK g_Hook = NULL;
	//PVOID PshareM = NULL;


	OutputDebugString("[+]sewinImjecr Enter!");

	ModuleHandle = LoadLibrary(szDllPath);
	if (!ModuleHandle)
	{
		int a = GetLastError();
		OutputDebugString("[+]LoadLibrary Error");
		return false;
	}
	FunctionAddress = (DWORD)GetProcAddress(ModuleHandle, "inStart");

	if (!FunctionAddress)
	{
		OutputDebugString("[+]GetProcAddress Error");
		return false;
	}

	dwThreadId = GetTargetThreadIdFromProcessName(szProcessName);
	if (!dwThreadId)
	{
		return false;
	}

	g_Hook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)FunctionAddress, ModuleHandle, dwThreadId);
	if (!g_Hook)
	{
		OutputDebugString("[+]SetwindowHookEx \n");
		return false;
	}

	OutputDebugString("[!]SetWindowHKInject Exit ! \n");
	bok = true;
	if (ModuleHandle)
	{
		FreeLibrary(ModuleHandle);
		UnhookWindowsHookEx(g_Hook);
	}
	return bok;


}


UINT32 GetTargetThreadIdFromProcessName(char* ProcessName)
{
	PROCESSENTRY32 pe;
	HANDLE SnapshotHandle = NULL;
	HANDLE ProcessHandle = NULL;
	BOOL Return, ProcessFound = false;
	UINT32 pTID, ThreadID;

	SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (SnapshotHandle == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, "获取拍照句柄失败", "tool", NULL);
		return false;
	}
	pe.dwSize = sizeof(PROCESSENTRY32);
	Return = Process32First(SnapshotHandle, &pe);
	while (Return)
	{
		if (strcmp(pe.szExeFile, ProcessName) == 0)
		{
			ProcessFound = TRUE;
			break;
		}
		Return = Process32Next(SnapshotHandle, &pe);
		pe.dwSize = sizeof(PROCESSENTRY32);
	}

	CloseHandle(SnapshotHandle);
	//通过fs寄存器获取TID
	_asm
	{
		mov eax, fs: [0x18]
		add eax, 36
		mov[pTID], eax
	}
	ProcessHandle = OpenProcess(PROCESS_VM_READ, false, pe.th32ProcessID);
	ReadProcessMemory(ProcessHandle, (LPVOID)pTID, &ThreadID, 4, NULL);
	CloseHandle(ProcessHandle);

	return ThreadID;

}


//获取共享内存中的数据
void GetMappingBuffer()
{


	//char* buff = (char*)malloc(4096);

	HANDLE hHapFile = NULL;
	LPCTSTR pBuf = NULL;

	//第一个参数 是否联到文件上 -1 则不联系到文件上只分配物理页
	//参数二：安全描述符 一般填空就行
	//参数三：是否提供可读可写
	//参数四：高32位大小 一般用不到 填0即可
	//参数五：需要提供多少的物理页
	//参数六：是否提供共享 
	hHapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x1000, "共享内存");
	if (hHapFile == NULL)
	{
		printf("创建或打开共享内存失败 %d", GetLastError());
		return;
	}
	//将物理页与线性地址进行映射
	//第一个参数： 创建的物理页的句柄
	//第二个参数： 映射后的访问类型 
	//第三个参数： 高32位  用不到填0就行
	//第四个参数： 低32位  偏移 一般从0开始就行
	//第四个参数： 文件映射的字节数 一般申请多大的物理页 就映射多大
	pBuf = (LPCTSTR)MapViewOfFile(hHapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0x1000);

	//写入数据
	while (TRUE)
	{
		int data = getchar();
		if (data == '7')
		{
			break;
		}
		memcpy((PVOID)pBuf, "7", 4);
		printf("写入数据：%s", pBuf);
	}
	UnmapViewOfFile(pBuf);
	CloseHandle(hHapFile);


	return;
}

void ReadMappingBuffer()
{
	HANDLE hMutex = NULL;
	while (true)
	{
		hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, "WndMutex");
		if (NULL == hMutex)
		{
			continue;
		}
		Sleep(200);

		WaitForSingleObject(hMutex, INFINITE);

		HANDLE hFileMap = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, "WndData");

#if 0
		HWND* pData = (HWND*)MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		HWND hGet = *pData;
#else
		char* pData = (char*)MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, 1024);
		printf("获取数据：%s", pData);
#endif
		SetEvent(hMutex);

		UnmapViewOfFile(pData);

		ReleaseMutex(hMutex);
	}
}

void regeditRead_Write()
{
	HKEY keyz;
	char* Register =(char*) "Software\\Microsoft\\Windows\\CurrentVersion\\Run";//这是要写进的注册表的地方
	char* Myapp = (char*)"C:\\Users\\Administrator\\Desktop\\ctfmon.exe";//这是我们需要自启动的程序的绝对路径

	//打开注册表启动项 
	if (RegOpenKeyExA(HKEY_CURRENT_USER, Register, 0, KEY_ALL_ACCESS, &keyz) != ERROR_SUCCESS)
	{
		RegSetValueExA(keyz, "Mytest", 0, REG_SZ, (BYTE*)Myapp, strlen(Myapp));
		//关闭注册表
		RegCloseKey(keyz);
		printf("succeed!\n");//执行成功输出
	}
	else
	{
		return;
		printf("Failed!");//执行失败
	}
}

//--------------------
DWORD GetAilgnmentSize(DWORD Size, DWORD align)
{
	DWORD SizeAlign = (Size / align) * align;
	if (SizeAlign == 0)
	{
		return align;
	}
	else if (SizeAlign < Size)
	{
		return GetAilgnmentSize(SizeAlign + align, align);
	}
	return SizeAlign;
}


void Disk()
{
	//获取当前操作系统有几个 磁盘  需将得到的数值转成16进制 在转 2进制
	/*	DWORD Logical =  GetLogicalDrives();*/

	//获取一个磁盘的字符串
	// 	DWORD dwMaxLength = 100;
	// 	char szBuffer[100] = { 0 };
	// 	GetLogicalDriveStrings(dwMaxLength, szBuffer);

	//获取磁盘类型 根据返回值对应MSDN 介绍 获取内容
	/*	UINT uin = GetDriveType("C://");*/

	//获取磁盘的类型 详细信息
	TCHAR szVolummeName[260] = { 0 };
	DWORD dwVolummeSerial = 0;
	DWORD dwVolMaxLength = 0;
	DWORD dwFileSystem = 0;
	TCHAR szFileSystem[260] = { 0 };

	GetVolumeInformation(
		"F:\\",					//IN  磁盘驱动器代码字符串
		szVolummeName,			//OUT 磁盘驱动器卷的名称
		260,					//IN  磁盘驱动器卷标名称长度
		&dwVolummeSerial,		//OUT 磁盘驱动器卷标序列号（不是磁盘序列号，该号是磁盘出厂时生产厂家为区别产品而设置的，就像人的身份证）
		&dwVolMaxLength,		//OUT 系统允许的最大文件名长度
		&dwFileSystem,			//OUT 文件系统标识
		szFileSystem,			//OUT 文件系统名称
		260						//IN  文件操作系统名称长度
	);

}


void FileStruct()
{
	//创建目录
	CreateDirectory("C:\\A", NULL);

	//删除目录
	RemoveDirectory("C:\\A");

	//修改目录名称
	MoveFile("C:\\B", "C:\\C");

	//获取程序的当前目录
	CHAR szCurrentDirectoryPath[MAX_PATH] = { 0 };
	GetCurrentDirectory(MAX_PATH, szCurrentDirectoryPath);
	printf("当前的文件目录在：%s \n", szCurrentDirectoryPath);

	//设置程序的当前目录
	SetCurrentDirectory("C:\\");
	CreateDirectory("123", NULL);
	//不设置则在程序的当前目录进行创建
	CreateDirectory("A", NULL);
}


void TextFile()
{
	//创建文件
	//参数一：文件路径
	//参数二：文件的读写属性
	//参数三：操作时是否阻止其他进程对其操作
	//参数四：一般为空
	//参数五：打开文件还是创建文件
	//参数六：文件的属性 是否隐藏
	//参数七：一般为空
	HANDLE hFile = CreateFile(
		"F:\\A.txt",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_HIDDEN,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		DWORD a = GetLastError();
	}

	//获取文件长度
	DWORD dwHigh = 0;
	GetFileSize(hFile, &dwHigh);

	//获取文件属性和信息
	WIN32_FILE_ATTRIBUTE_DATA data = { 0 };
	GetFileAttributesEx("C\\DbgView", GetFileExInfoStandard, &data);

	//读取文件
	LPSTR lpFileData = (LPSTR)malloc(dwHigh);
	ZeroMemory(lpFileData, dwHigh);
	//设置读取位置
	SetFilePointer(hFile, 1, NULL, FILE_BEGIN);
	DWORD Length = 0;
	ReadFile(hFile, lpFileData, dwHigh, &Length, NULL);

	//写入文件
	TCHAR szBuffer[] = { "你笑志祥凉的早，志祥笑你玩的少" };
	DWORD dwWritten = 0;
	WriteFile(hFile, szBuffer, strlen(szBuffer), &dwWritten, NULL);

	//拷贝文件
	//第三个参数 如果此参数为TRUE并且lpNewFileName指定的新文件 已经存在，则该函数将失败。如果此参数为 FALSE并且新文件已经存在，则该函数将覆盖现有文件并成功执行。
	CopyFile("c\\old.txt", "c\\new.txt", false);

	//删除文件
	DeleteFile("C:\\old.txt");




	//查找文件 
	// 	FindFirstFile();
	// 
	// 	FindNextFile();


	free(lpFileData);
	CloseHandle(hFile);
}