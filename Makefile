generate:
	go generate

build:
	D:\Go\go1.17.3\bin\go build -ldflags -H=windowsgui -o wsl2-ssh-pageant.exe

install: build
	mv wsl2-ssh-pageant.exe ~/.ssh/

listen: build
	socat UNIX-LISTEN:ssh.sock,fork EXEC:./wsl2-ssh-pageant.exe

copywin: build
	copy wsl2-ssh-pageant.exe E:\\wsl2-ssh-pageant.exe