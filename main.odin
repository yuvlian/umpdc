package main

import "base:runtime"
import "core:log"
import "core:thread"
import "shared:il2cure/e9c2da9/console"
import "shared:il2cure/e9c2da9/extra"
import "shared:il2cure/e9c2da9/hook"
import "shared:il2cure/e9c2da9/il2cpp"
import "cfg"
import "patches"

main :: proc () {
	if runtime.dll_forward_reason == .Process_Attach {
		thread.create_and_start(mod_thread)
	}
}

mod_thread :: proc () {
	cfg.load()

	loggers := console.create_loggers(cfg.LOG_FILE_NAME)
	defer console.destroy_loggers(loggers)

	context.logger = console.choose_logger(loggers)
	context.logger.lowest_level = cfg.get_log_level()

	patches.detour_logger = context.logger

	if err := console.init("Echium"); err != nil {
		log.warnf("console attach failed: %v (file log still active)", err)
	}
	defer console.uninit()

	patches.ga = extra.spin_until_ga_load()

	resolvers := make(map[string]il2cpp.Api_Resolver)
	resolvers[il2cpp.IL2CPP_STRING_NEW_LEN] = il2cpp.Pattern(cfg.cfg.il2cpp_string_new_len_pat)

	ok := il2cpp.init_map(resolvers, build_table = false)
	delete(resolvers)
	if !ok {
		log.error("il2cpp init failed?")
		extra.exit_if_ctrl_c()
		return
	}

	installers := []proc() -> bool {
		patches.install_addr_patch,
		patches.install_make_url_patch,
		patches.install_rsa_patch,
		patches.install_uncensor_peek,
	}

	applied := 0
	for install in installers {
		if install() {
			applied += 1
		}
	}

	if apn, aok := find_or_load_apn(); aok {
		patches.apn = apn
		applied += 1 if patches.install_apn_alloc() else 0
	} else {
		log.error("failed to get apn?")
		extra.exit_if_ctrl_c()
		return
	}

	log.infof("%v patches active", applied)

	extra.exit_if_ctrl_c()
	hook.uninstall_all()
	il2cpp.shutdown()
}
