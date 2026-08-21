package patches

import "base:runtime"
import "core:log"
import "core:strings"
import "shared:il2cure/e9c2da9/hook"
import "shared:il2cure/e9c2da9/il2cpp"
import "../cfg"

Make_Initial_Url_Proc :: #type proc "c" (
	rcx: rawptr,
	rdx: rawptr,
	r8:  rawptr,
	r9:  rawptr,
) -> rawptr

orig_miu: Make_Initial_Url_Proc

install_make_url_patch :: proc () -> bool {
	if !cfg.cfg.redirect_http {
		log.debug("http redirect disabled. install skipped.")
		return false
	}

	target := resolve_target(ga, cfg.cfg.make_initial_url_pat)
	if target == 0 {
		log.error("make_initial_url pattern not found. install failed.")
		return false
	}

	tramp, hok := hook.hook_inline_address(target, rawptr(patched_miu))
	if !hok {
		log.error("make_initial_url inline hook not ok. install failed.")
		return false
	}

	orig_miu = cast(Make_Initial_Url_Proc)tramp

	log.info("install finished.")
	return true
}

patched_miu :: proc "c" (
	rcx: rawptr,
	rdx: rawptr,
	r8:  rawptr,
	r9:  rawptr,
) -> rawptr {
	context = runtime.default_context()
	context.logger = detour_logger

	s_obj := il2cpp.Il2CppString(uintptr(rcx))
	url, uok := il2cpp.string_to_utf8(s_obj)
	if !uok {
		return orig_miu(rcx, rdx, r8, r9)
	}
	defer delete(url)

	redirect := cfg.cfg.redirect_http && (
		strings.contains(url, "mihoyo.com") ||
		strings.contains(url, "hoyoverse.com") ||
		strings.contains(url, "bhsr.com") ||
		strings.contains(url, "starrails.com")
	)

	if !redirect {
		return orig_miu(rcx, rdx, r8, r9)
	}

	target_url := cfg.cfg.sdk_url
	if p := path_after_authority(url, strings.index(url, "://") + 3); p != "" {
		target_url = strings.concatenate({cfg.cfg.sdk_url, p}, context.temp_allocator)
	}

	log.debugf("%s -> %s", url, target_url)
	ns := il2cpp.string_new(target_url)

	if target_url != cfg.cfg.sdk_url {
		delete(target_url, context.temp_allocator)
	}
	return orig_miu(rawptr(ns), rdx, r8, r9)
}
