package cfg

import "core:encoding/json"
import "core:log"
import "core:os"
import "shared:il2cure/e9c2da9/scan"

CONFIG_FILE_NAME :: "Echium.json"
LOG_FILE_NAME    :: "Echium.log"

UNK :: scan.WILDCARD

Config :: struct {
	log_level:                 uint,
	redirect_http:             bool,
	patch_rsa:                 bool,
	patch_censorship:          bool,
	sdk_url:                   string,
	il2cpp_string_new_len_pat: []u16,
	make_initial_url_pat:      []u16,
	set_dither_pat:            []u16,
	apn_alloc_pat:             []u16,
	sdk_public_key_pat:        []u16,
	sdk_public_key_xml:        string,
	sdk_public_key_pem:        string,
}

cfg := Config {
	log_level                 = 1,
	redirect_http             = true,
	patch_rsa                 = true,
	patch_censorship          = true,
	sdk_url                   = "http://127.0.0.1:21000",
	il2cpp_string_new_len_pat = {232, UNK, UNK, UNK, UNK, 235, UNK, 49, 192, 72, 137, 6, 72, 139, 71, UNK, 72, 137, 70, UNK, 242, 15, 16, 71},
	make_initial_url_pat      = {85, 65, 86, 86, 87, 83, 72, 129, 236, 144, 0, 0, 0, 72, 141, 172, 36, UNK, UNK, UNK, UNK, 72, 199, 69, UNK, UNK, UNK, UNK, UNK, 72, 133, 201, 116},
	set_dither_pat            = {232, UNK, UNK, UNK, UNK, 132, 192, 117, UNK, 199, 67},
	apn_alloc_pat             = {232, UNK, UNK, UNK, UNK, 65, 137, 191},
	sdk_public_key_pat        = {72, 139, 13, UNK, UNK, UNK, UNK, 76, 137, 226, 232, UNK, UNK, UNK, UNK, 72, 137, 198, 72, 139, 13, UNK, UNK, UNK, UNK, 232, UNK, UNK, UNK, UNK, 72, 137, 199, 72, 139, 13},
	sdk_public_key_xml        = "<RSAKeyValue><Exponent>AQAB</Exponent><Modulus>hEegnKISgDas5VTuRBUlixB+bvmPvXKa3kVO22UEZjPGMUFLmIl3DhH+dsZo7qJn/GfJCUkP1FA0MJ5Bj8PX8IatLJKIJ9dMCNdnAlkXTlMg86QQAhHZN83vP4swj5ILcrGNKl3YAZ49fvzo7nheuTt0/40f0HkHdNa1dUHECBs=</Modulus></RSAKeyValue>",
	sdk_public_key_pem        = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCER6CcohKANqzlVO5EFSWLEH5u\n+Y+9cpreRU7bZQRmM8YxQUuYiXcOEf52xmjuomf8Z8kJSQ/UUDQwnkGPw9fwhq0s\nkogn10wI12cCWRdOUyDzpBACEdk3ze8/izCPkgtysY0qXdgBnj1+/OjueF65O3T/\njR/QeQd01rV1QcQIGwIDAQAB\n-----END PUBLIC KEY-----",
}

get_log_level :: proc () -> log.Level {
	switch cfg.log_level {
	case 0:
		return log.Level.Debug
	case 1:
		return log.Level.Info
	case 2:
		return log.Level.Warning
	case 3:
		return log.Level.Error
	case:
		return log.Level.Fatal
	}
}

load :: proc () {
	c := cfg
	data, err := os.read_entire_file(CONFIG_FILE_NAME, context.allocator)
	if err != nil {
		log.infof("failed to read %s, using defaults. err=%v", CONFIG_FILE_NAME, err)
		return
	}
	defer delete(data)
	if err := json.unmarshal(data, &c); err != nil {
		log.errorf("failed to parse %s, using defaults. err=%v", CONFIG_FILE_NAME, err)
		return
	}
	log.infof("loaded %s (log_level=%v)", CONFIG_FILE_NAME, c.log_level)
	cfg = c
}
