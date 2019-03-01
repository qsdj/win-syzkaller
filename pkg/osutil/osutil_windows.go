// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !appengine

package osutil

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

func HandleInterrupts(shutdown chan struct{}) {
}

func RemoveAll(dir string) error {
	return os.RemoveAll(dir)
}

func prolongPipe(r, w *os.File) {
}

func CreateMemMappedFile(size int) (f *os.File, mem []byte, err error) {
	f, err = ioutil.TempFile("./", "syzkaller-shm")
	if err != nil {
		err = fmt.Errorf("failed to create temp file: %v", err)
		return
	}
	if err = f.Truncate(int64(size)); err != nil {
		err = fmt.Errorf("failed to truncate shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	fname := f.Name()
	f.Close()

	f, err = os.OpenFile(fname, os.O_RDWR, DefaultFilePerm)
	if err != nil {
		err = fmt.Errorf("failed to open shm file: %v", err)
		os.Remove(fname)
		return
	}
	/*
		key, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			err = fmt.Errorf("failed to encode file name: %v", err)
			return
		}
	*/
	h := syscall.Handle(f.Fd())
	h, err = syscall.CreateFileMapping(
		h, nil,
		syscall.PAGE_READWRITE, 0, uint32(size), nil)
	if err != nil {
		err = fmt.Errorf("failed to create file mapping: %v", err)
		return
	}
	v, err := syscall.MapViewOfFile(h, syscall.FILE_MAP_WRITE, 0, 0, 0)
	if err != nil {
		err = fmt.Errorf("failed to map file: %v", err)
		return
	}
	var sl = struct {
		addr uintptr
		len  int
		cap  int
	}{v, size, size}
	mem = *(*[]byte)(unsafe.Pointer(&sl))

	return
	//return nil, nil, fmt.Errorf("CreateMemMappedFile is not implemented")
}

func CloseMemMappedFile(f *os.File, mem []byte) error {
	addr := uintptr(unsafe.Pointer(&mem[0]))
	err1 := syscall.UnmapViewOfFile(addr)
	err2 := f.Close()
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	default:
		return nil
	}
}

func ProcessExitStatus(ps *os.ProcessState) int {
	return ps.Sys().(syscall.WaitStatus).ExitStatus()
}

func Sandbox(cmd *exec.Cmd, user, net bool) error {
	return nil
}

func SandboxChown(file string) error {
	return nil
}

func setPdeathsig(cmd *exec.Cmd) {
}
