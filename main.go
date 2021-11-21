package main

//go:generate go run github.com/go-bindata/go-bindata/go-bindata -pkg main -o assets.go assets/

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/apenwarr/fixconsole"
	"github.com/blackreloaded/wsl2-ssh-pageant/assets"
	"github.com/blackreloaded/wsl2-ssh-pageant/manager"
	"github.com/getlantern/systray"
	"github.com/lxn/win"
	"github.com/ncruces/zenity"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

const (
	// Windows constats
	invalidHandleValue = ^windows.Handle(0)
	pageReadWrite      = 0x4
	fileMapWrite       = 0x2

	// ssh-agent/Pageant constants
	agentMaxMessageLength = 8192
	agentCopyDataID       = 0x804e50ba

	cERROR_PIPE_NOT_CONNECTED syscall.Errno = 233
)

var (
	verbose               = flag.Bool("verbose", false, "Enable verbose logging")
	logFile               = flag.String("logfile", "wsl2-gpg-ssh.log", "Path to logfile")
	gpg                   = flag.String("gpg", "", "Make GPG Proxy with this pipe name")
	gpgConfigBasepath     = flag.String("gpgConfigBasepath", "", "gpg config path on windows")
	ssh                   = flag.String("ssh", "", "windows ssh mode")
	enableSystray         = flag.Bool("systray", false, "Have icon down in systray to control the process")
	winssh                = flag.String("winssh", "", "create a named pipe for ssh in windows")
	setAuthSock           = flag.Bool("set-win-sock", false, "set the SSH_AUTH_SOCK env in windows after execution")
	force                 = flag.Bool("force", false, "Force destruction and overwite or existing sockets a aa a a aa")
	installPaegentService = flag.Bool("install-agent-service", false, "install windows service")
	failureMessage        = [...]byte{0, 0, 0, 1, 5}
)

// copyDataStruct is used to pass data in the WM_COPYDATA message.
// We directly pass a pointer to our copyDataStruct type, we need to be
// careful that it matches the Windows type exactly
type copyDataStruct struct {
	dwData uintptr
	cbData uint32
	lpData uintptr
}

var wg sync.WaitGroup
var namedPipeFullName = "\\\\.\\pipe\\" + *winssh

func queryPageant(buf []byte) (result []byte, errs []error) {
	if len(buf) > agentMaxMessageLength {
		errs = append(errs, errors.New("Message too long"))
		return
	}
	pAgent, _ := syscall.UTF16PtrFromString("Pageant")
	hwnd := win.FindWindow(pAgent, pAgent)

	// Launch gpg-connect-agent
	if hwnd == 0 {
		log.Println("launching gpg-connect-agent")
		err := exec.Command("gpg-connect-agent", "/bye").Run()
		if err != nil {
			errs = append(errs, err)
		}
	}

	hwnd = win.FindWindow(pAgent, pAgent)
	if hwnd == 0 {
		errs = append(errs, errors.New("could not find Pageant window"))
		return
	}

	// Adding process id in order to support parrallel requests.
	requestName := "WSLPageantRequest" + strconv.Itoa(os.Getpid())
	mapName := fmt.Sprintf(requestName)

	mapNameUtf, _ := syscall.UTF16PtrFromString(mapName)
	fileMap, err := windows.CreateFileMapping(invalidHandleValue, nil, pageReadWrite, 0, agentMaxMessageLength, mapNameUtf)
	if err != nil {
		errs = append(errs, err)
		return
	}
	defer func() {
		err := windows.CloseHandle(fileMap)
		if err != nil {
			errs = append(errs, err)
		}
	}()

	sharedMemory, err := windows.MapViewOfFile(fileMap, fileMapWrite, 0, 0, 0)
	if err != nil {
		errs = append(errs, errors.New("could not find Pageant window"))
		return
	}
	defer func(addr uintptr) {
		err := windows.UnmapViewOfFile(addr)
		if err != nil {
			errs = append(errs, err)
		}
	}(sharedMemory)

	sharedMemoryArray := (*[agentMaxMessageLength]byte)(unsafe.Pointer(sharedMemory))
	copy(sharedMemoryArray[:], buf)

	mapNameWithNul := mapName + "\000"

	// We use our knowledge of Go strings to get the length and pointer to the
	// data and the length directly
	cds := copyDataStruct{
		dwData: agentCopyDataID,
		cbData: uint32(((*reflect.StringHeader)(unsafe.Pointer(&mapNameWithNul))).Len),
		lpData: ((*reflect.StringHeader)(unsafe.Pointer(&mapNameWithNul))).Data,
	}

	ret := win.SendMessage(hwnd, win.WM_COPYDATA, 0, uintptr(unsafe.Pointer(&cds)))
	if ret == 0 {
		errs = append(errs, errors.New("WM_COPYDATA failed"))
		return
	}

	memLen := binary.BigEndian.Uint32(sharedMemoryArray[:4])
	memLen += 4

	if memLen > agentMaxMessageLength {
		errs = append(errs, errors.New("return message too long"))
		return nil, errs
	}

	result = make([]byte, memLen)
	copy(result, sharedMemoryArray[:memLen])

	return
}

var done = make(chan bool, 1)

func pageant() {

	if *verbose {
		//Setting logput to file because we use stdout for communication
		f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		log.SetOutput(f)
		defer f.Close()
	}

	var unix net.Listener

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		switch sig {
		case os.Interrupt:
			log.Printf("Caught signal")
			done <- true
		case os.Kill:
			log.Printf("Caught Kill")
			done <- true
			os.Exit(0)
		}
	}()

	if *ssh != "" {
		handleSSH(ssh, unix, done)
	}
	if *winssh != "" {
		handleWinSSH(done)
	}
	if *gpg != "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal("failed to find user home dir")
		}
		basePath := *gpgConfigBasepath
		// fallback to default location if not specified
		if basePath == "" {
			basePath = filepath.Join(homeDir, "AppData", "Roaming", "gnupg")
			_, err := os.Stat(filepath.Join(basePath, *gpg))
			if err != nil {
				basePath = filepath.Join(homeDir, "AppData", "Local", "gnupg")
			}
		}
		handleGPG(filepath.Join(basePath, *gpg))
		return
	}
}

func createSockets(path *string, ls net.Listener, done chan bool) {
	_, err := os.Stat(*path)
	if err == nil || !os.IsNotExist(err) {
		if *force {
			// If the socket file already exists then unlink it
			err = syscall.Unlink(*path)
			if err != nil {
				log.Fatalf("Failed to unlink socket %s, error '%s'\n", *path, err)
			}
		} else {
			log.Fatalf("Error: the SSH_AUTH_SOCK file already exists. Please delete it manually or use --force option.")
		}
	}

	ls, err = net.Listen("unix", *path)
	if err != nil {
		log.Fatalf("Could not listen on socket %s, error '%s'\n", *path, err)
	}
}

func handleConnection(conn net.Conn) {
	wg.Add(1)
	defer wg.Done()
	defer conn.Close()

	for {
		lenBuf := make([]byte, 4)
		byteLen := bytes.NewBuffer(lenBuf)
		_, err := io.CopyBuffer(byteLen, conn, lenBuf)
		if err != nil {
			if *verbose {
				log.Printf("io.CopyBuffer error '%s'", err)
			}
			return
		}

		buffLen := binary.BigEndian.Uint32(lenBuf)
		rawBytes := make([]byte, buffLen)
		_, err = io.CopyBuffer(conn, bytes.NewReader(rawBytes), lenBuf)
		if err != nil {
			if *verbose {
				log.Printf("io.CopyBuffer error '%s'", err)
			}
			return
		}
		result, errs := queryPageant(append(lenBuf, rawBytes...))
		for err := range errs {
			// If for some reason talking to Pageant fails we fall back to
			// sending an agent error to the client
			if *verbose {
				log.Printf("Pageant query error '%s'\n", err)
			}
			result = failureMessage[:]
		}

		_, err = io.Copy(conn, bytes.NewReader(result))
		if err != nil {
			if *verbose {
				log.Printf("net.Conn.Write error '%s'", err)
			}
			return
		}
	}
}

func listenLoop(ln net.Listener) {
	wg.Add(1)
	defer wg.Done()
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("net.Listener.Accept error '%s'\n", err)
			return
		}
		if *verbose {
			log.Printf("New connection: %s\n", conn)
		}

		go handleConnection(conn)
	}
}

func underlyingError(err error) error {
	if serr, ok := err.(*os.SyscallError); ok {
		return serr.Err
	}
	return err
}

func listenOverlapped(ol *overlappedFile) {
	defer ol.Close()
	defer wg.Done()
	wg.Add(1)
	for {
		readBytes := bytes.NewBuffer(make([]byte, agentMaxMessageLength))
		_, err := io.Copy(readBytes, ol)
		if err != nil {
			log.Printf("Error reading %s, %s", namedPipeFullName, err)
		}
		response, errs := queryPageant(readBytes.Bytes())
		if errs != nil {
			log.Printf("Error ")
		}
		_, err = io.Copy(ol, bytes.NewReader(response))
		if underlyingError(err) == windows.ERROR_BROKEN_PIPE || underlyingError(err) == cERROR_PIPE_NOT_CONNECTED {
			// The named pipe is closed and there is no more data to read. Since
			// named pipes are not bidirectional, there is no way for the other side
			// of the pipe to get more data, so do not wait for the stdin copy to
			// finish.
			if *verbose {
				log.Println("copy from pipe to stdout finished: pipe closed")
			}
			os.Exit(0)
		}
		if err != nil {

			log.Printf("error writing to %s '%s'", namedPipeFullName, err)
			break
		}

	}
}
func handleWinSSH(done chan bool) {
	wg.Add(1)
	defer wg.Done()
	utfName, _ := windows.UTF16PtrFromString(namedPipeFullName)

	h, err := windows.CreateFile(utfName, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)

	if err != nil {
		log.Fatalf("Unable to open named pipe %s", namedPipeFullName)
	}
	ol := newOverlappedFile(h)
	o := windows.Overlapped{HEvent: h}
	err = windows.ConnectNamedPipe(h, &o)
	if err != nil {
		log.Fatalf("Unable to connect to named pipe %s", namedPipeFullName)
	}
	if *verbose {
		log.Printf("New connection: %s\n", namedPipeFullName)
	}
	go func() {
		listenOverlapped(ol)

		// If for some reason our listener breaks, kill the program
		done <- true
	}()

}

func handleGPG(path string) {
	wg.Add(1)
	defer wg.Done()
	var port int
	var nonce [16]byte

	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}

	reader := bufio.NewReader(file)
	tmp, _, err := reader.ReadLine()
	port, err = strconv.Atoi(string(tmp))
	n, err := reader.Read(nonce[:])
	if err != nil {
		if *verbose {
			log.Printf("Could not read port from gpg nonce: %v\n", err)
		}
		return
	}

	if n != 16 {
		if *verbose {
			log.Printf("Could not connet gpg: incorrect number of bytes for nonceRead incorrect number of bytes for nonce\n")
		}
		return
	}

	gpgConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		if *verbose {
			log.Printf("Could not connet gpg: %v\n", err)
		}
		return
	}

	_, err = gpgConn.Write(nonce[:])
	if err != nil {
		if *verbose {
			log.Printf("Could not authenticate gpg: %v\n", err)
		}
		return
	}

	go func() {
		wg.Add(1)
		defer wg.Done()
		_, err := io.Copy(gpgConn, os.Stdin)
		if err != nil {
			if *verbose {
				log.Printf("Could not copy gpg data from assuan socket to socket: %v\n", err)
			}
			return
		}
	}()

	_, err = io.Copy(os.Stdout, gpgConn)

	if err != nil {
		if *verbose {
			log.Printf("Could not copy gpg data from socket to assuan socket: %v\n", err)
		}
		return
	}

}

func handleSSH(unixSocket *string, unix net.Listener, done chan bool) {
	createSockets(unixSocket, unix, done)
	defer unix.Close()
	log.Printf("Listening on Unix socket: %s\n", *unixSocket)
	go func() {
		listenLoop(unix)

		// If for some reason our listener breaks, kill the program
		done <- true
	}()
}

type menuItem *systray.MenuItem

func onSystrayReady() {
	systray.SetTitle("WSL2-SSH-Pageant")

	data, err := assets.Asset("assets/app.ico")
	if err == nil {
		systray.SetIcon(data)
	}

	systray.SetTooltip("WSL2-SSH-Pageant")
	quit := systray.AddMenuItem("Quit", "Quits this app")

	go func() {
		for {
			select {
			case <-quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func main() {
	fixconsole.FixConsoleIfNeeded()
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(1)
	}
	exe, _ := os.Executable()
	if *installPaegentService {
		if *winssh != "" {
			config := mgr.Config{
				ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
				StartType:    mgr.StartAutomatic,
				ErrorControl: mgr.ErrorSevere,
				DisplayName:  "WSL2 SSH Agent Proxy",
			}
			var args = []string{"--winssh ", *winssh}
			errs2 := manager.InstallService("wsl2-ssh-pageant", exe, config, args...)
			if errs2 != nil {
				_ = zenity.Error(errs2[0].Error(), zenity.Title("Error Creating Service"), zenity.Icon(zenity.ErrorIcon))
				log.Fatalf("Error creating service %s", "wsl2-ssh-pageant")
			}
			if *setAuthSock {
				key, err := registry.OpenKey(registry.LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\Session Manager\\Environment", registry.READ|registry.WRITE)
				if err != nil {
					_ = zenity.Error(err.Error(), zenity.Title("Error Setting SSH_AUTH_SOCK"), zenity.Icon(zenity.ErrorIcon))
					log.Fatalf("Unable to open registry key %v", "HKLM"+"System\\CurrentControlSet\\Control\\Session Manager\\Environment")
				}
				err = key.SetStringValue("SSH_AUTH_SOCK", namedPipeFullName)
				if err != nil {
					_ = zenity.Error(err.Error(), zenity.Title("Error Setting SSH_AUTH_SOCK"), zenity.Icon(zenity.ErrorIcon))
					log.Fatalf("Unable to set SSH_AUTH_SOCK env var to %s", namedPipeFullName)
					return
				}
			}
			return
		} else {
			_ = zenity.Error("You must specify --winssh when installing a service", zenity.Title("WinSSH needed"), zenity.Icon(zenity.ErrorIcon))
			log.Fatalf("You must specify --winssh when installing a service")
		}
	}

	go func() {
		// Wait until we are signalled as finished
		<-done

		// If for some reason our listener breaks, kill the program
		if *enableSystray {
			systray.Quit()
		}
	}()
	pageant()
	if *enableSystray {
		systray.Run(onSystrayReady, nil)
	}
	<-done
}
