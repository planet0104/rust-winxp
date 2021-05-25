set RUSTFLAGS=-Ctarget-feature=+crt-static -Clink-args=/subsystem:console,5.01
cargo build --release
copy target\release\httptool.dll ..\cpp\httptool.dll
cd ..\cpp
g++ -o main.exe main.cpp -L./ -lhttptool
cd ..