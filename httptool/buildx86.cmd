set RUSTFLAGS=-Ctarget-feature=+crt-static -Clink-args=/subsystem:console,5.01
cargo build --target i686-pc-windows-msvc --release
copy target\i686-pc-windows-msvc\release\httptool.dll cpp\httptool.dll
:: 在windows xp下使用   g++ -o main.exe main.cpp -L./ -lhttptool -m32