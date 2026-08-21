package patches

import "core:log"
import "shared:il2cure/e9c2da9/il2cpp"
import "../cfg"

install_rsa_patch :: proc () -> bool {
	if !cfg.cfg.patch_rsa {
		log.debug("rsa patch disabled. install skipped.")
		return false
	}

	slot := resolve_target(ga, cfg.cfg.sdk_public_key_pat)
	if slot == 0 {
		log.error("sdk_public_key pattern not found. install failed.")
		return false
	}

	ns := il2cpp.string_new(cfg.cfg.sdk_public_key_xml)
	(cast(^il2cpp.Il2CppString)(slot))^ = ns

	log.info("install finished.")
	return true
}
