package patches

import "core:log"
import "shared:il2cure/e9c2da9/hook"
import "shared:il2cure/e9c2da9/scan"
import "../cfg"

// i like to stare at boothill's metal dih
install_uncensor_peek :: proc () -> bool {
	if !cfg.cfg.patch_censorship {
		log.debug("censorship patch disabled. install skipped.")
		return false
	}

	site, sok := scan.find_pattern_in_module(ga, cfg.cfg.set_dither_pat)
	if !sok {
		log.error("set_dither pattern not found. install failed.")
		return false
	}

	if !hook.patch_call(site, rawptr(patched_set_dither)) {
		log.error("failed to patch call. install failed.")
		return false
	}

	log.info("install finished.")
	return true
}

patched_set_dither :: proc "c" (a: rawptr, b: rawptr, c: rawptr) -> uintptr {
	return 0
}
