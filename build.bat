gcc dllmain.c -o umpdc.dll -static-libgcc -shared -O3 -s -flto -march=native -mtune=native -Wl,--gc-sections -fdata-sections -ffunction-sections -lpsapi -lws2_32
