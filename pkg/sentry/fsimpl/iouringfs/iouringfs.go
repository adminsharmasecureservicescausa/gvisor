// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package iouringfs provides a filesystem implementation for IO_URING basing
// it on anonfs.
package iouringfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// IoUring  implements io_uring struct. See io_uring/io_uring.c.
type IoUring struct {
	head uint32
	tail uint32
}

// IoUringCqe implements IO completion data structure (Completion Queue Entry)
// io_uring_cqe struct. See include/uapi/linux/io_uring.h.
type IoUringCqe struct {
	userData uint64
	res      int16
	flags    uint32
}

// FileDescription implements vfs.FileDescriptionImpl for file-based IO_URING.
// It is based on io_rings struct. See io_uring/io_uring.c.
//
// +stateify savable
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	mf       *pgalloc.MemoryFile
	mfp      pgalloc.MemoryFileProvider
	frSqRing memmap.FileRange
	frCqRing memmap.FileRange
	frSqes   memmap.FileRange
}

var _ vfs.FileDescriptionImpl = (*fileDescription)(nil)

// New creates a new iouring fd.
func New(ctx context.Context, vfsObj *vfs.VirtualFilesystem, entries uint32, params *linux.IoUringParams, paramsUser hostarch.Addr) (*vfs.FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("[io_uring]")
	defer vd.DecRef(ctx)

	mfp := pgalloc.MemoryFileProviderFromContext(ctx)
	if mfp == nil {
		panic(fmt.Sprintf("context.Context %T lacks non-nil value for key %T", ctx, pgalloc.CtxMemoryFileProvider))
	}

	// TODO: for now assume that number of entries is a power of two. But we really need to round it
	// up to the nearest power of two.
	numSqEntries := entries
	numCqEntries := 2 * numSqEntries
	// Allocate enough space to store the given number of pointers to SQEs along with additional
	// information. Each submission queue entry represented as a pointer. And additional 40 bytes are
	// for 5 pointers to head, tail, ringMask, ringEntries, and flags.
	effectiveSize := uint64(40 + numSqEntries*8)
	frSqRing, err := mfp.MemoryFile().Allocate(effectiveSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		return nil, linuxerr.ENOMEM
	}
	// Allocate enough space to store the given number of CQEs along with additional information.
	// Each completion queue entry IoUringCqe occupies 16 bytes (8 + 4 + 4). And additional 32 bytes
	// are for four pointers to head, tail, ringMask, and ringEntries.
	effectiveSize = uint64(32 + numCqEntries*16)
	frCqRing, err := mfp.MemoryFile().Allocate(effectiveSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		return nil, linuxerr.ENOMEM
	}
	// Allocate number enough space to store the given number of submission queue entries.
	// TODO: allocation size should depend on number of entries and and size of struct for
	// submission queue entry, but not being fixed.
	effectiveSize = uint64(4096)
	frSqes, err := mfp.MemoryFile().Allocate(effectiveSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		return nil, linuxerr.ENOMEM
	}

	iouringfd := &fileDescription{
		mf:       mfp.MemoryFile(),
		mfp:      mfp,
		frSqRing: frSqRing,
		frCqRing: frCqRing,
		frSqes:   frSqes,
	}

	// iouringfd is always set up with read/write mode.
	// See io_uring/io_uring.c:io_uring_install_fd().
	if err := iouringfd.vfsfd.Init(iouringfd, uint32(linux.O_RDWR), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
		DenySpliceIn:      true,
	}); err != nil {
		return nil, err
	}

	return &iouringfd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *fileDescription) Release(context.Context) {
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *fileDescription) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return vfs.GenericConfigureMMap(&fd.vfsfd, fd, opts)
}

// AddMapping implements memmap.Mappable.AddMapping.
func (fd *fileDescription) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (fd *fileDescription) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (fd *fileDescription) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (fd *fileDescription) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	expectedAccessType := hostarch.AccessType{
		Read:    true,
		Write:   true,
		Execute: false,
	}
	if at != expectedAccessType {
		return nil, &memmap.BusError{linuxerr.EPERM}
	}

	var err error
	var offset uint64
	var fr memmap.FileRange
	switch offset = optional.Start; offset {
	case linux.IORING_OFF_SQ_RING:
		offset = fd.frSqRing.Start
		fr = fd.frSqRing
	case linux.IORING_OFF_CQ_RING:
		offset = fd.frCqRing.Start
		fr = fd.frCqRing
	case linux.IORING_OFF_SQES:
		offset = fd.frSqes.Start
		fr = fd.frSqes
	default:
		return nil, &memmap.BusError{linuxerr.EFAULT}
	}

	if required.End > fr.Length() {
		return nil, &memmap.BusError{linuxerr.EFAULT}
	}

	if source := optional.Intersect(memmap.MappableRange{0, fr.Length()}); source.Length() != 0 {
		return []memmap.Translation{
			{
				Source: source,
				File:   fd.mf,
				Offset: offset,
				Perms:  at,
			},
		}, err
	}

	return nil, err
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (fd *fileDescription) InvalidateUnsavable(ctx context.Context) error {
	return nil
}
