package patches

import "core:log"
import "core:strings"
import "shared:il2cure/e9c2da9/scan"

// set in main
detour_logger: log.Logger

// GameAssembly.dll
ga: scan.Module_Info

// AccountPlatNative.dll
apn: scan.Module_Info

resolve_target :: proc (module: scan.Module_Info, pat: []u16) -> uintptr {
	addr, ok := scan.find_pattern_in_module(module, pat)
	if !ok {
		return 0
	}
	if t := scan.resolve_call_rel32(addr); t != 0 {
		return t
	}
	if t := scan.resolve_rip_rel(addr); t != 0 {
		return t
	}
	return addr
}

path_after_authority :: proc (s: string, search_from: int) -> string {
	if i := strings.index(s[search_from:], "/"); i >= 0 {
		return s[search_from + i:]
	}
	return ""
}
