#include<bits/stdc++.h>
#include <windows.h>
using namespace std;
void str2paste(const std::string& str) {
    // 打开剪切板
    if (OpenClipboard(NULL)) {
        // 清空剪切板，准备接收新数据
        EmptyClipboard();
 
        // 分配全局内存以存放字符串
        size_t len = str.length() + 1; // 包括结尾的空字符
        HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, len);
        if (hglbCopy) {
            // 锁定全局内存以访问它
            LPSTR lptstrCopy = static_cast<LPSTR>(GlobalLock(hglbCopy));
            if (lptstrCopy) {
                // 复制字符串到全局内存
                memcpy(lptstrCopy, str.c_str(), len);
                // 解锁全局内存
                GlobalUnlock(hglbCopy);
 
                // 将全局内存句柄设置为剪切板的内容
                if (!SetClipboardData(CF_TEXT, hglbCopy)) {
                    // 如果设置失败，释放内存
                    GlobalFree(hglbCopy);
                }
            } else {
                // 如果锁定失败，释放内存
                GlobalFree(hglbCopy);
            }
        }
        // 关闭剪切板
        CloseClipboard();
    }
}

