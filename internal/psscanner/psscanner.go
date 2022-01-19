package psscanner

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type PSScanner struct {
	enablePpid   bool
	eventCh      chan<- PSEvent
	maxCmdLength int
}

type PSEvent struct {
	UID  int
	PID  int
	PPID int
	CMD  string
	CWD string
}

func check_permission(cwd string,cmdline string,uid string) string {
	black_filenames := []string{"","/dev/null", "/dev/pts/0","/dev/pts/1","/dev/pts/2","/dev/pts/3","/dev/pts/4","/dev/pts/5"}
	fmt.Println("start....")
	fmt.Println("cwd: ",cwd)
	fmt.Println("cmdline: ",cmdline)
	org_cmdline := cmdline
	cmd := strings.TrimSpace(cmdline)
	cmdlines := strings.Split(cmd," ")
	for _,cmdline := range cmdlines{
		filename := strings.TrimSpace(cmdline)
		fmt.Println("split filename: ",filename)
		okfile := "/tmp/pspyokfile.txt"
		f, err3 := os.OpenFile(okfile,os.O_RDWR|os.O_CREATE|os.O_APPEND,0644)
		if err3 != nil{
			fmt.Println("create pspyokfile fail")
		}
		defer f.Close()
		if (!IsDir(filename) && !in(filename,black_filenames)){
			if strings.HasPrefix(filename,"/"){
				file,err := os.OpenFile(filename,os.O_WRONLY,2)
				if err != nil {
					fmt.Println("文件以写模式打开失败,可能无法提权", err)
				} else{
					okfilename := filename
					fmt.Println("可能可以提权，文件名为 ",okfilename)
					f.WriteString("文件名为: " + okfilename + " UID为: " + uid + " 进程为: " + org_cmdline + "\n")
					fmt.Println("write ok")

				}
				defer file.Close()
			}else{
				file,err := os.OpenFile(fmt.Sprintf(cwd + "/" + filename),os.O_WRONLY,2)
				if err != nil {
					fmt.Println("文件file以写模式打开失败,可能无法提权", err)
				} else{
					okfilename := fmt.Sprintf(cwd + "/" + filename)
					fmt.Println("可能可以提权，文件名为 ",fmt.Sprintf(okfilename))
					f.WriteString("文件名为: " + okfilename + " UID为: " + uid + " 进程为: " + org_cmdline + "\n")
					fmt.Println("write ok")
				}
				defer file.Close()
			}
		}else{
			fmt.Print("文件夹: ",filename)
		}
		f.Close()
	}
	return "ok"
}

func in(target string, str_array []string) bool {
	sort.Strings(str_array)
	index := sort.SearchStrings(str_array, target)
	if index < len(str_array) && str_array[index] == target {
		return true
	}
	return false
}

func check_fd(fd string,uid int,cmdline string) string {
	black_fds := []string{"/dev/null", "/dev/pts/0","/dev/pts/1","/dev/pts/2","/dev/pts/3","/dev/pts/4","/dev/pts/5"}
	okfile := "/tmp/pspyokfile.txt"
	f, err3 := os.OpenFile(okfile,os.O_RDWR|os.O_CREATE|os.O_APPEND,0644)
	if err3 != nil{
		fmt.Println("create file fail")
	}
	defer f.Close()
	if (!IsDir(fd) && !in(fd,black_fds)){
		fmt.Println("fd为: ",fd)
		if strings.HasPrefix(fd,"/"){
			file,err := os.OpenFile(fd,os.O_WRONLY,2)
			if err != nil {
				fmt.Println("文件以写模式打开失败,可能无法提权", err)
			} else{
				okfilename := fd
				fmt.Println("可能可以提权，fd对应的文件为 ",okfilename)
				f.WriteString(fmt.Sprintf("fd对应的文件为: %s UID为: %d fd对应的进程为: %s \n",okfilename,uid,cmdline))
				fmt.Println("write ok")

			}
			defer file.Close()
		}
	}else{
		fmt.Print("文件夹: ",fd)
	}
	f.Close()
	return "fdok"
}

func (evt PSEvent) String() string {
	uid := strconv.Itoa(evt.UID)
	if evt.UID == -1 {
		uid = "???"
	}

	if evt.PPID == -1 {
		check_permission(evt.CWD,evt.CMD,uid)
		fdinfo := getfdfinfo(evt.PID)
		for fdfiles := range(fdinfo){
			//fmt.Print(fdinfo[fdfiles])
			check_fd(fdinfo[fdfiles],evt.UID,evt.CMD)
		}
		return fmt.Sprintf("UID=%-5s PID=%-6d | %s", uid, evt.PID, evt.CMD)
	}

	check_permission(evt.CWD,evt.CMD,uid)
	fdinfo := getfdfinfo(evt.PID)
	for fdfiles := range(fdinfo){
		//fmt.Print(fdinfo[fdfiles])
		check_fd(fdinfo[fdfiles],evt.UID,evt.CMD)
	}
	return fmt.Sprintf(
		"UID=%-5s PID=%-6d PPID=%-6d | %s", uid, evt.PID, evt.PPID, evt.CMD)
}

var (
	// identify ppid in stat file
	ppidRegex, _ = regexp.Compile("\\d+ \\(.*\\) [[:alpha:]] (\\d+)")
	// hook for testing, directly use Lstat syscall as os.Lstat hides data in Sys member
	lstat = syscall.Lstat
	// hook for testing
	open = func(s string) (io.ReadCloser, error) {
		return os.Open(s)
	}
)

func NewPSScanner(ppid bool, cmdLength int) *PSScanner {
	return &PSScanner{
		enablePpid:   ppid,
		eventCh:      nil,
		maxCmdLength: cmdLength,
	}
}

func (p *PSScanner) Run(triggerCh chan struct{}) (chan PSEvent, chan error) {
	eventCh := make(chan PSEvent, 100)
	p.eventCh = eventCh
	errCh := make(chan error)
	pl := make(procList)

	go func() {
		for {
			<-triggerCh
			pl.refresh(p)
		}
	}()
	return eventCh, errCh
}

func IsDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}


func getfdfinfo(pid int) (openfiles map[string]string){
	fdpath := fmt.Sprintf("/proc/%d/fd",pid)
	openfiles = make(map[string]string)
	fds,_ := ioutil.ReadDir(fdpath)
	for _,fd := range(fds){
		fpath, err := filepath.EvalSymlinks(filepath.Join(fdpath, fd.Name()))
		if err != nil {
			continue
		}
		fmt.Println(fpath)
		openfiles["isfile"] = fpath
	}
	return openfiles
}


func (p *PSScanner) processNewPid(pid int) {
	statInfo := syscall.Stat_t{}
	errStat := lstat(fmt.Sprintf("/proc/%d", pid), &statInfo)
	cmdLine, errCmdLine := readFile(fmt.Sprintf("/proc/%d/cmdline", pid), p.maxCmdLength)
	ppid, _ := p.getPpid(pid)
	cwdinfo, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		fmt.Sprintf("%d cwd打开失败",pid)
	}
	cmd := "???" // process probably terminated
	if errCmdLine == nil {
		for i := 0; i < len(cmdLine); i++ {
			if cmdLine[i] == 0 {
				cmdLine[i] = 32
			}
		}
		cmd = string(cmdLine)

	}

	uid := -1
	if errStat == nil {
		uid = int(statInfo.Uid)
	}

	p.eventCh <- PSEvent{UID: uid, PID: pid, PPID: ppid, CMD: cmd,CWD: cwdinfo}
}

func (p *PSScanner) getPpid(pid int) (int, error) {
	if !p.enablePpid {
		return -1, nil
	}

	stat, err := readFile(fmt.Sprintf("/proc/%d/stat", pid), 512)
	if err != nil {
		return -1, err
	}

	if m := ppidRegex.FindStringSubmatch(string(stat)); m != nil {
		return strconv.Atoi(m[1])
	}
	return -1, errors.New("corrupt stat file")
}

// no nonsense file reading
func readFile(filename string, maxlen int) ([]byte, error) {
	file, err := open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buffer := make([]byte, maxlen)
	n, err := file.Read(buffer)
	if err != io.EOF && err != nil {
		return nil, err
	}
	return buffer[:n], nil
}
