#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <psapi.h>

typedef struct {
    char sdk_url[256];
    bool redirect_http;
    char il2cpp_string_new_len_pat[256];
    char make_initial_url_pat[256];
    char set_dither_pat[256];
    char apn_alloc_pat[256];
    char sdk_public_key_pat[256];
    char sdk_public_key_xml[4096];
    char sdk_public_key_pem[4096];
} Config;

Config g_config;

void unescape_newlines(char* s) {
    char* d = s;
    while (*s) {
        if (*s == '\\' && *(s + 1) == 'n') {
            *d++ = '\n';
            s += 2;
        } else {
            *d++ = *s++;
        }
    }
    *d = '\0';
}

void load_config() {
    char ini_path[MAX_PATH];
    GetModuleFileNameA(NULL, ini_path, MAX_PATH);

    char* last_slash = strrchr(ini_path, '\\');
    if (last_slash) {
        *last_slash = '\0';
    }
    strcat_s(ini_path, MAX_PATH, "\\umpdc.ini");

    GetPrivateProfileStringA(
        "umpdc",
        "SDK_URL",
        "http://127.0.0.1:21000",
        g_config.sdk_url,
        256,
        ini_path
    );

    char buf[16];
    GetPrivateProfileStringA(
        "umpdc",
        "REDIRECT_HTTP",
        "true",
        buf,
        16,
        ini_path
    );
    g_config.redirect_http = _stricmp(buf, "true") == 0;

    GetPrivateProfileStringA(
        "umpdc",
        "IL2CPP_STRING_NEW_LEN_PAT",
        "E8 ? ? ? ? EB ? 31 C0 48 89 06 48 8B 47 ? 48 89 46 ? F2 0F 10 47",
        g_config.il2cpp_string_new_len_pat,
        256,
        ini_path
    );

    GetPrivateProfileStringA(
        "umpdc",
        "MAKE_INITIAL_URL_PAT",
        "E8 ? ? ? ? 48 89 F9 48 89 C2 E8 ? ? ? ? 48 89 F9 4C 89 F2 E8 ? ? ? ? 48",
        g_config.make_initial_url_pat,
        256,
        ini_path
    );

    GetPrivateProfileStringA(
        "umpdc",
        "SET_DITHER_PAT",
        "E8 ? ? ? ? 84 C0 75 ? C7 43",
        g_config.set_dither_pat,
        256,
        ini_path
    );

    GetPrivateProfileStringA(
        "umpdc",
        "APN_ALLOC_PAT",
        "E8 ? ? ? ? 41 89 BF",
        g_config.apn_alloc_pat,
        256,
        ini_path
    );

    GetPrivateProfileStringA(
        "umpdc",
        "SDK_PUBLIC_KEY_PAT",
        "48 8B 0D ? ? ? ? 4C 89 E2 E8 ? ? ? ? 48 89 C6 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 89 C7 48 8B 0D",
        g_config.sdk_public_key_pat,
        256,
        ini_path
    );

    GetPrivateProfileStringA(
        "umpdc",
        "SDK_PUBLIC_KEY_XML",
        "",
        g_config.sdk_public_key_xml,
        4096,
        ini_path
    );

    GetPrivateProfileStringA(
        "umpdc",
        "SDK_PUBLIC_KEY_PEM",
        "",
        g_config.sdk_public_key_pem,
        4096,
        ini_path
    );

    unescape_newlines(g_config.sdk_public_key_xml);
    unescape_newlines(g_config.sdk_public_key_pem);
}

typedef struct {
    uint8_t v;
    bool w;
} PByte;

uintptr_t scan_site(const char* mod, const char* pat) {
    HMODULE h = GetModuleHandleA(mod);
    if (!h) return 0;

    MODULEINFO mi;
    GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi));

    uintptr_t start = (uintptr_t)mi.lpBaseOfDll;
    uintptr_t end = start + mi.SizeOfImage;

    PByte p[256];
    int n = 0;
    const char* c = pat;

    while (*c) {
        if (*c == ' ') {
            c++;
            continue;
        }

        if (*c == '?') {
            p[n++].w = true;
            c++;
            if (*c == '?') c++;
            continue;
        }

        p[n].v = (uint8_t)strtol(c, (char**)&c, 16);
        p[n++].w = false;
    }

    for (uintptr_t i = start; i < end - n; i++) {
        bool m = true;
        for (int j = 0; j < n; j++) {
            if (!p[j].w && p[j].v != *(uint8_t*)(i + j)) {
                m = false;
                break;
            }
        }
        if (m) return i;
    }

    return 0;
}

uintptr_t scan(const char* mod, const char* pat) {
    uintptr_t i = scan_site(mod, pat);
    if (i) {
        if (*(uint8_t*)i == 0xE8) {
            return i + 5 + *(int32_t*)(i + 1);
        }
        if (*(uint8_t*)i == 0x48 && *(uint8_t*)(i + 1) == 0x8B && *(uint8_t*)(i + 2) == 0x0D) {
            return i + 7 + *(int32_t*)(i + 3);
        }
        return i;
    }
    return 0;
}

uintptr_t find_cave(const char* mod) {
    HMODULE h = GetModuleHandleA(mod);
    if (!h) return 0;
    MODULEINFO mi;
    GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi));
    uintptr_t start = (uintptr_t)mi.lpBaseOfDll;
    uintptr_t end = start + mi.SizeOfImage;

    int n = 0;
    for (uintptr_t i = start; i < end; i++) {
        if (*(uint8_t*)i == 0x00 || *(uint8_t*)i == 0xCC) {
            if (++n >= 20) return i - 19;
        } else {
            n = 0;
        }
    }
    return 0;
}

void* hook(const char* mod, void* target, void* detour) {
    if (!target) return NULL;

    void* tramp = VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(tramp, target, 5);
    uint8_t* t_ptr = (uint8_t*)tramp;
    t_ptr[5] = 0xFF; t_ptr[6] = 0x25; *(uint32_t*)(t_ptr + 7) = 0;
    *(uint64_t*)(t_ptr + 11) = (uintptr_t)target + 5;

    uintptr_t relay = find_cave(mod);
    if (relay) {
        DWORD old;
        VirtualProtect((void*)relay, 14, PAGE_EXECUTE_READWRITE, &old);
        uint8_t* r_ptr = (uint8_t*)relay;
        r_ptr[0] = 0xFF; r_ptr[1] = 0x25; *(uint32_t*)(r_ptr + 2) = 0;
        *(uint64_t*)(r_ptr + 6) = (uintptr_t)detour;

        VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old);
        uint8_t* target_ptr = (uint8_t*)target;
        target_ptr[0] = 0xE9;
        *(int32_t*)(target_ptr + 1) = (int32_t)(relay - ((uintptr_t)target + 5));
        VirtualProtect(target, 5, old, &old);
    }
    
    return tramp;
}

void hook_iat(const char* mod, const char* imp_mod, const char* func, void* detour, void** original) {
    HMODULE h = GetModuleHandleA(mod);
    if (!h) return;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)h;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)h + dos->e_lfanew);
    DWORD imp_va = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!imp_va) return;
    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)h + imp_va);
    while (imp->Name) {
        if (_stricmp((const char*)((uintptr_t)h + imp->Name), imp_mod) == 0) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uintptr_t)h + imp->FirstThunk);
            PIMAGE_THUNK_DATA orig = imp->OriginalFirstThunk ? (PIMAGE_THUNK_DATA)((uintptr_t)h + imp->OriginalFirstThunk) : thunk;
            while (thunk->u1.Function) {
                if (!(orig->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)h + orig->u1.AddressOfData);
                    if (_stricmp(ibn->Name, func) == 0) {
                        if (original) *original = (void*)thunk->u1.Function;
                        DWORD old;
                        VirtualProtect(&thunk->u1.Function, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &old);
                        thunk->u1.Function = (uintptr_t)detour;
                        VirtualProtect(&thunk->u1.Function, sizeof(uintptr_t), old, &old);
                        return;
                    }
                }
                thunk++; orig++;
            }
        }
        imp++;
    }
}

void hook_iat_all(const char* imp_mod, const char* func, void* detour, void** original) {
    HMODULE mods[1024];
    DWORD cb;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &cb)) {
        for (unsigned int i = 0; i < (cb / sizeof(HMODULE)); i++) {
            char name[MAX_PATH];
            if (GetModuleBaseNameA(GetCurrentProcess(), mods[i], name, MAX_PATH)) {
                hook_iat(name, imp_mod, func, detour, original);
            }
        }
    }
}

typedef struct {
    void* k;
    void* m;
    uint32_t len;
    uint16_t chars[1];
} IString;

IString* (*il2cpp_new)(const char*, uint32_t);

IString* i_new(const char* s) {
    return il2cpp_new(s, (uint32_t)strlen(s));
}

void i_to_u8(IString* s, char* o, int n) {
    if (!s) {
        *o = 0;
        return;
    }
    int l = WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)s->chars, s->len, o, n - 1, 0, 0);
    o[l] = 0;
}

typedef int (WSAAPI* gai_t)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
gai_t o_gai;

int WSAAPI h_gai(PCSTR n, PCSTR s, const ADDRINFOA* h, PADDRINFOA* r) {
    if (n && strstr(n, "globaldp-") && (strstr(n, "bhsr.com") || strstr(n, "starrails.com"))) {
        printf("[getaddrinfo] %s -> 0.0.0.0\n", n);
        return o_gai("0.0.0.0", s, h, r);
    }
    return o_gai(n, s, h, r);
}

void* (*o_apn_alloc)(void*, void*, void*, void*);

void* h_apn_alloc(void* rcx, void* rdx, void* r8, void* r9) {
    const char* s = (const char*)rdx;
    size_t l = (size_t)r8;

    if (s) {
        if (strncmp(s, "https://", 8) == 0 && strstr(s, ".mihoyo.com")) {
            char buf[512];
            strcpy_s(buf, 512, g_config.sdk_url);
            const char* p = strchr(s + 8, '/');
            if (p) strcat_s(buf, 512, p);
            printf("[apn] %s -> %s\n", s, buf);
            return o_apn_alloc(rcx, buf, (void*)strlen(buf), r9);
        }

        if (l == 268 && strncmp(s, "-----BEGIN PUBLIC KEY-----", 26) == 0) {
            printf("[apn] public key replaced\n");
            return o_apn_alloc(rcx, g_config.sdk_public_key_pem, (void*)strlen(g_config.sdk_public_key_pem), r9);
        }
    }
    return o_apn_alloc(rcx, rdx, r8, r9);
}

void* (*o_miu)(void*, void*, void*, void*);

void* h_miu(void* rcx, void* rdx, void* r8, void* r9) {
    IString* s_obj = (IString*)rcx;
    char buf[512];
    i_to_u8(s_obj, buf, 512);

    bool redirect = g_config.redirect_http && (
        strstr(buf, "mihoyo.com") || strstr(buf, "hoyoverse.com") ||
        strstr(buf, "bhsr.com") || strstr(buf, "starrails.com")
    );

    if (redirect) {
        char n_buf[512];
        strcpy_s(n_buf, 512, g_config.sdk_url);
        const char* p = strstr(buf, "://");
        if (p) {
            p += 3;
            p = strchr(p, '/');
            if (p) strcat_s(n_buf, 512, p);
        }
        printf("[unity] %s -> %s\n", buf, n_buf);
        return o_miu(i_new(n_buf), rdx, r8, r9);
    }
    return o_miu(rcx, rdx, r8, r9);
}

size_t h_zero(void* a, void* b, void* c) {
    return 0;
}

void patch_call(uintptr_t site, void* detour) {
    if (!site || *(uint8_t*)site != 0xE8) return;
    intptr_t dist = (intptr_t)detour - ((intptr_t)site + 5);
    if (dist > 0x7FFFFFFF || dist < -0x7FFFFFFF) return;

    DWORD old;
    VirtualProtect((void*)(site + 1), 4, PAGE_EXECUTE_READWRITE, &old);
    *(int32_t*)(site + 1) = (int32_t)dist;
    VirtualProtect((void*)(site + 1), 4, old, &old);
}

DWORD WINAPI Main(LPVOID lp) {
    AllocConsole();
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);

    printf("[main] starting patch...\n");
    load_config();

    while (!GetModuleHandleA("GameAssembly.dll")) Sleep(100);
    printf("[main] GameAssembly.dll found\n");

    bool http_ok = true;
    bool rsa_ok = true;
    bool dither_ok = true;

    il2cpp_new = (IString*(*)(const char*, uint32_t))scan("GameAssembly.dll", g_config.il2cpp_string_new_len_pat);
    if (il2cpp_new) {
        printf("[main] il2cpp_string_new_len: 0x%p\n", (void*)il2cpp_new);
    } else {
        printf("[main] il2cpp_string_new_len not found\n");
        http_ok = false;
        rsa_ok = false;
    }

    hook_iat_all("Ws2_32.dll", "getaddrinfo", h_gai, (void**)&o_gai);
    if (o_gai) {
        printf("[main] getaddrinfo hooked: 0x%p\n", (void*)o_gai);
    } else {
        printf("[main] couldnt hook getaddrinfo\n");
        http_ok = false;
    }

    uintptr_t miu = scan("GameAssembly.dll", g_config.make_initial_url_pat);
    if (miu && il2cpp_new) {
        o_miu = (void*(*)(void*, void*, void*, void*))hook("GameAssembly.dll", (void*)miu, h_miu);
        printf("[main] make_initial_url hooked: 0x%p\n", (void*)miu);
    } else {
        printf("[main] make_initial_url not found\n");
        http_ok = false;
    }

    uintptr_t dit_site = scan_site("GameAssembly.dll", g_config.set_dither_pat);
    if (dit_site) {
        printf("[main] set_dither patched: 0x%p\n", (void*)dit_site);
        patch_call(dit_site, h_zero);
    } else {
        printf("[main] set_dither not found\n");
        dither_ok = false;
    }

    uintptr_t key = scan("GameAssembly.dll", g_config.sdk_public_key_pat);
    if (key && il2cpp_new) {
        printf("[main] sdk_public_key pointer: 0x%p\n", (void*)key);
        *(IString**)key = i_new(g_config.sdk_public_key_xml);
    } else {
        printf("[main] sdk_public_key not found\n");
        rsa_ok = false;
    }

    if (!GetModuleHandleA("AccountPlatNative.dll")) LoadLibraryA("./StarRail_Data/Plugins/x86_64/AccountPlatNative.dll");
    while (!GetModuleHandleA("AccountPlatNative.dll")) Sleep(100);
    printf("[main] AccountPlatNative.dll found\n");

    uintptr_t apn = scan("AccountPlatNative.dll", g_config.apn_alloc_pat);
    if (apn) {
        o_apn_alloc = (void*(*)(void*, void*, void*, void*))hook("AccountPlatNative.dll", (void*)apn, h_apn_alloc);
        printf("[main] apn_alloc hooked: 0x%p\n", (void*)apn);
    } else {
        printf("[main] apn_alloc not found\n");
        http_ok = rsa_ok = false;
    }

    printf("[main] rsa patch: %s\n", rsa_ok ? "ok" : "fail");
    printf("[main] http redirect patch: %s\n", http_ok ? "ok" : "fail");
    printf("[main] avatar dither patch: %s\n", dither_ok ? "ok" : "fail");

    if (rsa_ok && http_ok && dither_ok) {
        printf("[main] all patched and ready~\n");
    } else {
        printf("[main] some patches failed. patterns might be outdated.\n");
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) {
    if (r == DLL_PROCESS_ATTACH) CreateThread(0, 0, Main, 0, 0, 0);
    return TRUE;
}
