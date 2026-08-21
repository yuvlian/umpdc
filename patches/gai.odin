package patches

import "base:runtime"
import "core:log"
import "core:strings"
import "shared:il2cure/e9c2da9/hook"
import "../cfg"

Get_Addr_Info_Proc :: #type proc "stdcall" (
	node:    cstring,
	service: cstring,
	hints:   rawptr,
	result:  rawptr,
) -> i32

orig_gai: Get_Addr_Info_Proc

install_addr_patch :: proc () -> bool {
	if !cfg.cfg.redirect_http {
		log.debug("http redirect disabled. install skipped.")
		return false
	}

	orig, ok := hook.hook_iat_all("Ws2_32.dll", "getaddrinfo", rawptr(patched_gai))
	if !ok {
		log.error("IAT hook not ok. install failed.")
		return false
	}

	orig_gai = cast(Get_Addr_Info_Proc)orig

	log.info("install finished.")
	return true
}

patched_gai :: proc "stdcall" (
	node:    cstring,
	service: cstring,
	hints:   rawptr,
	result:  rawptr,
) -> i32 {
	context = runtime.default_context()
	context.logger = detour_logger

	if node != nil {
		host := string(node)

		if strings.contains(host, "globaldp-") &&
		   (strings.contains(host, "bhsr.com") || strings.contains(host, "starrails.com")) {
			log.debugf("%s -> 0.0.0.0", host)
			return orig_gai("0.0.0.0", service, hints, result)
		}
	}

	return orig_gai(node, service, hints, result)
}
