// Copyright (c) 2015, Jesse Sipprell
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:

// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.

// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.

// * Neither the name of keyctl nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Based on the work of Jesse Sipprell's project https://github.com/jsipprell/keyctl
//
// https://github.com/jsipprell/keyctl/blob/master/sys_linux.go
//
// Modified by Antitree
// Copied by Brompwnie

package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

type keyId int32
type keyctlCommand int

const (
	// Only for 64 bit architecture
	syscall_keyctl   uintptr = 250
	syscall_add_key  uintptr = 248
	syscall_setfsgid uintptr = 123
)

const (
	keyctlGetKeyringId keyctlCommand = iota
	keyctlJoinSessionKeyring
	keyctlUpdate
	keyctlRevoke
	keyctlChown
	keyctlSetPerm
	keyctlDescribe
	keyctlClear
	keyctlLink
	keyctlUnlink
	keyctlSearch
	keyctlRead
	keyctlInstantiate
	keyctlNegate
	keyctlSetReqKeyKeyring
	keyctlSetTimeout
	keyctlAssumeAuthority
	keyctlGetPersistent
)

const (
	// you can reference builtin keyrings this way
	keySpecThreadKeyring      keyId = -1
	keySpecProcessKeyring     keyId = -2
	keySpecSessionKeyring     keyId = -3
	keySpecUserKeyring        keyId = -4
	keySpecUserSessionKeyring keyId = -5
	keySpecGroupKeyring       keyId = -6
	keySpecReqKeyAuthKey      keyId = -7
)

func (k *Key) populate_describe(bdesc []byte) error {
	// Parse the response from the describekeyid syscall
	// In the format of:
	// 	user;1000;1000;3f1000000;myname
	k.Valid = true // TODO do I need this here?
	aReturn := strings.Split(string(bdesc), ";")
	if len(aReturn) < 5 {
		return fmt.Errorf("Something wrong parsing describekeyid results: %s", string(bdesc))
	}

	// Populate info from results
	k.Type = aReturn[0]
	k.Uid = aReturn[1]
	k.Gid = aReturn[2]
	k.Perms = aReturn[3]
	k.Name = aReturn[4]

	// TODO not very useful results
	return nil
}

func (cmd keyctlCommand) String() string {
	switch cmd {
	case keyctlGetKeyringId:
		return "keyctlGetKeyringId"
	case keyctlJoinSessionKeyring:
		return "keyctlJoinSessionKeyring"
	case keyctlUpdate:
		return "keyctlUpdate"
	case keyctlRevoke:
		return "keyctlRevoke"
	case keyctlChown:
		return "keyctlChown"
	case keyctlSetPerm:
		return "keyctlSetPerm"
	case keyctlDescribe:
		return "keyctlDescribe"
	case keyctlClear:
		return "keyctlClear"
	case keyctlLink:
		return "keyctlLink"
	case keyctlUnlink:
		return "keyctlUnlink"
	case keyctlSearch:
		return "keyctlSearch"
	case keyctlRead:
		return "keyctlRead"
	case keyctlInstantiate:
		return "keyctlInstantiate"
	case keyctlNegate:
		return "keyctlNegate"
	case keyctlSetReqKeyKeyring:
		return "keyctlSetReqKeyKeyring"
	case keyctlSetTimeout:
		return "keyctlSetTimeout"
	case keyctlAssumeAuthority:
		return "keyctlAssumeAuthority"
	case keyctlGetPersistent:
		return "keyctlGetPersistent"
	}
	panic("bad arg")
}

func add_key(keyType, keyDesc string, payload []byte, id int32) (int32, error) {
	var (
		err    error
		errno  syscall.Errno
		b1, b2 *byte
		r1     uintptr
		pptr   unsafe.Pointer
	)

	if b1, err = syscall.BytePtrFromString(keyType); err != nil {
		return 0, err
	}

	if b2, err = syscall.BytePtrFromString(keyDesc); err != nil {
		return 0, err
	}

	if len(payload) > 0 {
		pptr = unsafe.Pointer(&payload[0])
	}
	r1, _, errno = syscall.Syscall6(syscall_add_key,
		uintptr(unsafe.Pointer(b1)),
		uintptr(unsafe.Pointer(b2)),
		uintptr(pptr),
		uintptr(len(payload)),
		uintptr(id),
		0)

	if errno != 0 {
		err = errno
		return 0, err
	}
	return int32(r1), nil
}

func listKeys(id keyId) ([]keyId, error) {
	var (
		b1             []byte
		size, sizeRead int
	)

	bsz := 4
	b1 = make([]byte, 16*bsz)
	size = len(b1)
	sizeRead = size + 1
	for sizeRead > size {
		r1, _, errno := syscall.Syscall6(syscall_keyctl, uintptr(keyctlRead), uintptr(id), uintptr(unsafe.Pointer(&b1[0])), uintptr(size), 0, 0)
		if errno != 0 {
			return nil, errno
		}

		if sizeRead = int(r1); sizeRead > size {
			b1 = make([]byte, sizeRead)
			size = sizeRead
			sizeRead++
		} else {
			size = sizeRead
		}
	}
	keys := make([]keyId, size/bsz)
	for i := range keys {
		keys[i] = *((*keyId)(unsafe.Pointer(&b1[i*bsz])))
	}

	return keys, nil
}

// func newKeyring(id keyId) (*keyring, error) {
// 	r1, _, errno := syscall.Syscall(syscall_keyctl, uintptr(keyctlGetKeyringId), uintptr(id), uintptr(1))
// 	if errno != 0 {
// 		return nil, errno
// 	}

// 	if id >= 0 {
// 		id = keyId(r1)
// 	}
// 	return &keyring{id: id}, nil
// }

func (k Key) describeKeyId() ([]byte, error) {
	var (
		b1             []byte
		size, sizeRead int
	)

	b1 = make([]byte, 64)
	size = len(b1)
	sizeRead = size + 1
	for sizeRead > size {
		r1, _, errno := syscall.Syscall6(syscall_keyctl, uintptr(keyctlDescribe), uintptr(keyId(k.KeyId)), uintptr(unsafe.Pointer(&b1[0])), uintptr(size), 0, 0)
		if errno != 0 {
			return nil, errno
		}
		if sizeRead = int(r1); sizeRead > size {
			b1 = make([]byte, sizeRead)
			size = sizeRead
			sizeRead++
		} else {
			size = sizeRead
		}
	}

	return b1[:size-1], nil
}

func keyctl_Read(id keyId, b *byte, size int) (int32, error) {
	v1, _, errno := syscall.Syscall6(syscall_keyctl, uintptr(keyctlRead), uintptr(id), uintptr(unsafe.Pointer(b)), uintptr(size), 0, 0)
	if errno != 0 {
		return -1, errno
	}

	return int32(v1), nil
}

func keyctl_Unlink(id, ring keyId) error {
	_, _, errno := syscall.Syscall(syscall_keyctl, uintptr(keyctlUnlink), uintptr(id), uintptr(ring))
	if errno != 0 {
		return errno
	}
	return nil
}

func keyctl_Link(id, ring keyId) error {
	_, _, errno := syscall.Syscall(syscall_keyctl, uintptr(keyctlLink), uintptr(id), uintptr(ring))
	if errno != 0 {
		return errno
	}
	return nil
}

func keyctl_Get_Persistent(uid int, ring keyId) error {
	fmt.Println("keyCtl_GetPersistent UID:", uid)
	fmt.Println("keyCtl_GetPersistent ring:", ring)
	// TODO the lookup for "GetPersistentId" is 17 but in reality it's 22
	// I have no idea where this is set and who sets it...
	// see https://github.com/torvalds/linux/blob/v5.4/include/uapi/linux/keyctl.h#L62
	_, _, errno := syscall.Syscall(syscall_keyctl, uintptr(22), uintptr(uid), uintptr(ring))
	if errno != 0 {
		return errno
	}
	return nil
}
