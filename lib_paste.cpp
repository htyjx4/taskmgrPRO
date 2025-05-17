#include<bits/stdc++.h>
#include <windows.h>
using namespace std;
void str2paste(const std::string& str) {
    // �򿪼��а�
    if (OpenClipboard(NULL)) {
        // ��ռ��а壬׼������������
        EmptyClipboard();
 
        // ����ȫ���ڴ��Դ���ַ���
        size_t len = str.length() + 1; // ������β�Ŀ��ַ�
        HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, len);
        if (hglbCopy) {
            // ����ȫ���ڴ��Է�����
            LPSTR lptstrCopy = static_cast<LPSTR>(GlobalLock(hglbCopy));
            if (lptstrCopy) {
                // �����ַ�����ȫ���ڴ�
                memcpy(lptstrCopy, str.c_str(), len);
                // ����ȫ���ڴ�
                GlobalUnlock(hglbCopy);
 
                // ��ȫ���ڴ�������Ϊ���а������
                if (!SetClipboardData(CF_TEXT, hglbCopy)) {
                    // �������ʧ�ܣ��ͷ��ڴ�
                    GlobalFree(hglbCopy);
                }
            } else {
                // �������ʧ�ܣ��ͷ��ڴ�
                GlobalFree(hglbCopy);
            }
        }
        // �رռ��а�
        CloseClipboard();
    }
}

