package main

import "core:log"
import "core:time"
import "core:dynlib"
import "shared:il2cure/e9c2da9/scan"

APN_DLL     :: "AccountPlatNative.dll"
APN_DLL_LOC :: "./StarRail_Data/Plugins/x86_64/" + APN_DLL

MAX_RETRIES_BEFORE_SELF_LOAD :: 10

find_or_load_apn :: proc() -> (scan.Module_Info, bool) {
    for _ in 0..<MAX_RETRIES_BEFORE_SELF_LOAD {
        if m, ok := scan.module_info_from_name(APN_DLL); ok {
            log.debug("game loaded apn.dll")
            return m, true
        }
        log.debug("cant find apn.dll, retrying in 100ms")
        time.sleep(100 * time.Millisecond)
    }

    if _, lok := dynlib.load_library(APN_DLL_LOC); lok {
        if m, sok := scan.module_info_from_name(APN_DLL); sok {
            log.debug("self loaded apn.dll")
            return m, true
        }
    }

    return {}, false
}
