#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdint.h>

static HMODULE g_real_wh = NULL;
static HMODULE real_wh(void) {
    if (!g_real_wh) {
        char sys[MAX_PATH];
        UINT n = GetSystemDirectoryA(sys, MAX_PATH - 16);
        if (n > 0 && n < MAX_PATH - 16) {
            lstrcatA(sys, "\\winhttp.dll");
            g_real_wh = LoadLibraryA(sys);
        }
    }
    return g_real_wh;
}

typedef void* (*fn_domain_get)(void);
typedef void** (*fn_domain_get_assemblies)(void*, size_t*);
typedef void* (*fn_assembly_get_image)(void*);
typedef void* (*fn_class_from_name)(void*, const char*, const char*);
typedef void* (*fn_class_get_method_from_name)(void*, const char*, int);

typedef int (*fn_il2cpp_init)(const char*);
typedef int (*fn_il2cpp_init_utf16)(const wchar_t*);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);

static fn_il2cpp_init g_real_init = NULL;
static fn_il2cpp_init_utf16 g_real_init_w = NULL;
static fn_GetProcAddress g_real_gpa = NULL;
static int g_patched = 0;

static void patch_integrity_now(void) {
    if (g_patched) return;
    HMODULE ga = GetModuleHandleA("GameAssembly.dll");
    if (!ga) return;
    fn_domain_get domain_get = (fn_domain_get)GetProcAddress(ga, "il2cpp_domain_get");
    fn_domain_get_assemblies domain_asms = (fn_domain_get_assemblies)GetProcAddress(ga, "il2cpp_domain_get_assemblies");
    fn_assembly_get_image asm_img = (fn_assembly_get_image)GetProcAddress(ga, "il2cpp_assembly_get_image");
    fn_class_from_name cls_from_name = (fn_class_from_name)GetProcAddress(ga, "il2cpp_class_from_name");
    fn_class_get_method_from_name cls_method = (fn_class_get_method_from_name)GetProcAddress(ga, "il2cpp_class_get_method_from_name");
    if (!domain_get || !domain_asms || !asm_img || !cls_from_name || !cls_method) return;

    void* dom = domain_get();
    if (!dom) return;
    size_t count = 0;
    void** asms = domain_asms(dom, &count);
    if (!asms || count == 0) return;

    for (size_t i = 0; i < count; i++) {
        void* img = asm_img(asms[i]);
        if (!img) continue;
        void* klass = cls_from_name(img, "", "FileIntegrityCheck");
        if (!klass) continue;
        void* mi = cls_method(klass, "CheckFileIntegrity", 0);
        if (mi) {
            void* fn = *(void**)mi;
            if (fn) {
                DWORD old = 0;
                if (VirtualProtect(fn, 16, PAGE_EXECUTE_READWRITE, &old)) {
                    uint8_t* p = (uint8_t*)fn;
                    p[0] = 0xB0; /* mov al, 1 */
                    p[1] = 0x01;
                    p[2] = 0xC3; /* ret */
                    VirtualProtect(fn, 16, old, &old);
                    FlushInstructionCache(GetCurrentProcess(), fn, 16);
                    g_patched = 1;
                    return;
                }
            }
        }
    }
}

static int hook_il2cpp_init(const char* name) {
    int r = g_real_init ? g_real_init(name) : 0;
    patch_integrity_now();
    return r;
}

static int hook_il2cpp_init_utf16(const wchar_t* name) {
    int r = g_real_init_w ? g_real_init_w(name) : 0;
    patch_integrity_now();
    return r;
}

static int ascii_eq(const char* a, const char* b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

static FARPROC WINAPI hook_GetProcAddress(HMODULE mod, LPCSTR name) {
    FARPROC res = g_real_gpa ? g_real_gpa(mod, name) : NULL;
    if (res && ((uintptr_t)name > 0xFFFF)) {
        if (ascii_eq(name, "il2cpp_init")) {
            g_real_init = (fn_il2cpp_init)res;
            return (FARPROC)hook_il2cpp_init;
        }
        if (ascii_eq(name, "il2cpp_init_utf16")) {
            g_real_init_w = (fn_il2cpp_init_utf16)res;
            return (FARPROC)hook_il2cpp_init_utf16;
        }
    }
    return res;
}

static void hook_unityplayer_iat(void) {
    HMODULE up = GetModuleHandleA("UnityPlayer.dll");
    if (!up) return;
    uint8_t* base = (uint8_t*)up;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    IMAGE_DATA_DIRECTORY imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!imp_dir.VirtualAddress) return;

    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + imp_dir.VirtualAddress);
    HMODULE k32 = GetModuleHandleA("KERNEL32.dll");
    FARPROC target_gpa = k32 ? GetProcAddress(k32, "GetProcAddress") : NULL;
    if (!target_gpa) return;

    for (; imp->Name; imp++) {
        IMAGE_THUNK_DATA* oft = (IMAGE_THUNK_DATA*)(base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        IMAGE_THUNK_DATA* ft  = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        for (; oft->u1.AddressOfData; oft++, ft++) {
            if (!(oft->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + oft->u1.AddressOfData);
                if (ascii_eq((const char*)ibn->Name, "GetProcAddress") || (FARPROC)ft->u1.Function == target_gpa) {
                    DWORD old = 0;
                    if (VirtualProtect(&ft->u1.Function, sizeof(void*), PAGE_READWRITE, &old)) {
                        g_real_gpa = (fn_GetProcAddress)ft->u1.Function;
                        ft->u1.Function = (ULONGLONG)hook_GetProcAddress;
                        VirtualProtect(&ft->u1.Function, sizeof(void*), old, &old);
                        return;
                    }
                }
            }
        }
    }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        hook_unityplayer_iat();
    }
    return TRUE;
}

typedef uintptr_t (WINAPI *fn_any)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

uintptr_t WINAPI wrap_DllCanUnloadNow(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "DllCanUnloadNow") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_DllGetClassObject(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "DllGetClassObject") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_Private1(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "Private1") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_SvchostPushServiceGlobals(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "SvchostPushServiceGlobals") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpAddRequestHeaders(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpAddRequestHeaders") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpAddRequestHeadersEx(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpAddRequestHeadersEx") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpAutoProxySvcMain(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpAutoProxySvcMain") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpCheckPlatform(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpCheckPlatform") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpCloseHandle(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpCloseHandle") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnect(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnect") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionDeletePolicyEntries(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionDeletePolicyEntries") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionDeletePolicyEntriesByAppSid(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionDeletePolicyEntriesByAppSid") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionDeleteProxyInfo(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionDeleteProxyInfo") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionFreeNameList(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionFreeNameList") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionFreeProxyInfo(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionFreeProxyInfo") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionFreeProxyList(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionFreeProxyList") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionGetNameList(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionGetNameList") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionGetProxyInfo(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionGetProxyInfo") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionGetProxyList(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionGetProxyList") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionOnlyConvert(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionOnlyConvert") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionOnlyReceive(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionOnlyReceive") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionOnlySend(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionOnlySend") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionSetPolicyEntries(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionSetPolicyEntries") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionSetProxyInfo(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionSetProxyInfo") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpConnectionUpdateIfIndexTable(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpConnectionUpdateIfIndexTable") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpCrackUrl(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpCrackUrl") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpCreateProxyList(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpCreateProxyList") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpCreateProxyManager(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpCreateProxyManager") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpCreateProxyResolver(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpCreateProxyResolver") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpCreateProxyResult(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpCreateProxyResult") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpCreateUiCompatibleProxyString(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpCreateUiCompatibleProxyString") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpCreateUrl(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpCreateUrl") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpDetectAutoProxyConfigUrl(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpDetectAutoProxyConfigUrl") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpFreeProxyResult(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpFreeProxyResult") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpFreeProxyResultEx(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpFreeProxyResultEx") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpFreeProxySettings(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpFreeProxySettings") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpFreeProxySettingsEx(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpFreeProxySettingsEx") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpFreeQueryConnectionGroupResult(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpFreeQueryConnectionGroupResult") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetDefaultProxyConfiguration(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetDefaultProxyConfiguration") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetIEProxyConfigForCurrentUser(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetIEProxyConfigForCurrentUser") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetProxyForUrl(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetProxyForUrl") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetProxyForUrlEx(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetProxyForUrlEx") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetProxyForUrlEx2(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetProxyForUrlEx2") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetProxyForUrlHvsi(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetProxyForUrlHvsi") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetProxyResult(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetProxyResult") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetProxyResultEx(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetProxyResultEx") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetProxySettingsEx(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetProxySettingsEx") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetProxySettingsResultEx(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetProxySettingsResultEx") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetProxySettingsVersion(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetProxySettingsVersion") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpGetTunnelSocket(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpGetTunnelSocket") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpOpen(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpOpen") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpOpenRequest(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpOpenRequest") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpPacJsWorkerMain(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpPacJsWorkerMain") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpProbeConnectivity(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpProbeConnectivity") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpProtocolCompleteUpgrade(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpProtocolCompleteUpgrade") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpProtocolReceive(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpProtocolReceive") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpProtocolSend(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpProtocolSend") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpQueryAuthSchemes(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpQueryAuthSchemes") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpQueryConnectionGroup(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpQueryConnectionGroup") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpQueryDataAvailable(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpQueryDataAvailable") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpQueryHeaders(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpQueryHeaders") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpQueryHeadersEx(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpQueryHeadersEx") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpQueryOption(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpQueryOption") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpReadData(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpReadData") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpReadDataEx(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpReadDataEx") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpReadProxySettings(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpReadProxySettings") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpReadProxySettingsHvsi(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpReadProxySettingsHvsi") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpReceiveResponse(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpReceiveResponse") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpRefreshProxySettings(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpRefreshProxySettings") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpRegisterProxyChangeNotification(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpRegisterProxyChangeNotification") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpResetAutoProxy(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpResetAutoProxy") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpResolverGetProxyForUrl(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpResolverGetProxyForUrl") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpSaveProxyCredentials(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpSaveProxyCredentials") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpSendRequest(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpSendRequest") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpSetCredentials(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpSetCredentials") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpSetDefaultProxyConfiguration(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpSetDefaultProxyConfiguration") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpSetOption(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpSetOption") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpSetProxySettingsPerUser(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpSetProxySettingsPerUser") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpSetSecureLegacyServersAppCompat(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpSetSecureLegacyServersAppCompat") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpSetStatusCallback(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpSetStatusCallback") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpSetTimeouts(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpSetTimeouts") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpTimeFromSystemTime(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpTimeFromSystemTime") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpTimeToSystemTime(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpTimeToSystemTime") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpUnregisterProxyChangeNotification(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpUnregisterProxyChangeNotification") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpWebSocketClose(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpWebSocketClose") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpWebSocketCompleteUpgrade(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpWebSocketCompleteUpgrade") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpWebSocketQueryCloseStatus(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpWebSocketQueryCloseStatus") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpWebSocketReceive(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpWebSocketReceive") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpWebSocketSend(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpWebSocketSend") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpWebSocketShutdown(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpWebSocketShutdown") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpWriteData(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpWriteData") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
uintptr_t WINAPI wrap_WinHttpWriteProxySettings(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e, uintptr_t f, uintptr_t g, uintptr_t h) { HMODULE m = real_wh(); fn_any p = m ? (fn_any)GetProcAddress(m, "WinHttpWriteProxySettings") : NULL; return p ? p(a,b,c,d,e,f,g,h) : 0; }
