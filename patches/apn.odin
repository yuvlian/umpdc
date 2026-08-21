package patches

import "base:runtime"
import "core:log"
import "core:strings"
import "shared:il2cure/e9c2da9/hook"
import "../cfg"

Apn_Alloc_Proc :: #type proc "c" (
	rcx: rawptr,
	rdx: rawptr,
	r8:  rawptr,
	r9:  rawptr,
) -> rawptr

orig_apn_alloc: Apn_Alloc_Proc

install_apn_alloc :: proc () -> bool {
	target := resolve_target(apn, cfg.cfg.apn_alloc_pat)
	if target == 0 {
		log.error("apn_alloc pattern not found. install failed.")
		return false
	}

	tramp, hok := hook.hook_inline_address(target, rawptr(patched_apn_alloc))
	if !hok {
		log.error("apn_alloc inline hook not ok. install failed.")
		return false
	}

	orig_apn_alloc = cast(Apn_Alloc_Proc)tramp

	log.info("install finished.")
	return true
}

patched_apn_alloc :: proc "c" (
	rcx: rawptr,
	rdx: rawptr,
	r8:  rawptr,
	r9:  rawptr,
) -> rawptr {
	context = runtime.default_context()
	context.logger = detour_logger

	if rdx != nil {
		s_len := int(uintptr(r8))
		s := string((cast([^]u8)(rdx))[:s_len])

		if cfg.cfg.redirect_http && strings.has_prefix(s, "https://") &&
			strings.contains(s, ".mihoyo.com") {
			url_buf := cfg.cfg.sdk_url
			if p := path_after_authority(s, 8); p != "" {
				url_buf = strings.concatenate({cfg.cfg.sdk_url, p}, context.temp_allocator)
			}

			log.debugf("%s -> %s", s, url_buf)
			res := orig_apn_alloc(rcx,
				raw_data(url_buf), rawptr(uintptr(len(url_buf))), r9)

			if url_buf != cfg.cfg.sdk_url {
				delete(url_buf, context.temp_allocator)
			}
			return res
		}

		if cfg.cfg.patch_rsa && s_len == 268 &&
			strings.has_prefix(s, "-----BEGIN PUBLIC KEY-----") {
			log.debug("public key replaced")
			pem := cfg.cfg.sdk_public_key_pem
			return orig_apn_alloc(rcx, raw_data(pem), rawptr(uintptr(len(pem))), r9)
		}
	}

	return orig_apn_alloc(rcx, rdx, r8, r9)
}
