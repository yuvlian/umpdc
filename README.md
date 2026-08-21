# echium

patch for playing honkai: star rail private server made with using https://github.com/yuvlian/il2cure :D

last tested on hsr 4.4.55

## wyg?
- **http redirect**
- **rsa patch**
- **censorship patch**

## reqs

- odin https://github.com/odin-lang/Odin/releases
- git https://git-scm.com/install for installing il2cure (see `deps.ps1`)

## quick start

clone repo then just run `deps.ps1` and `build.ps1`. after that copy the `echium.dll` to same folder as `game.exe`, then rename the dll to `umpdc.dll`.

for configuration, you can copy `Echium.json` too and modify as needed.

you can also get prebuilt from https://github.com/yuvlian/echium/releases/

## packages

| package | what it does |
|---------|--------------|
| `main.odin` | dll entry |
| `apn_helper.odin` | helper for apn.dll |
| `cfg/` | json config |
| `patches/` | patch source files |

## license

MIT
