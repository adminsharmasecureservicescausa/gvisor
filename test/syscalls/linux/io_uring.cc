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

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include "test/util/io_uring_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(IoUringTest, ValidFD) {
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIoUringFD(1));
}

TEST(IoUringTest, ParamsNonZeroResv) {
  struct io_uring_params params;
  memset(&params, 0, sizeof(params));
  params.resv[1] = 1;
  ASSERT_THAT(IoUringSetup(1, &params), SyscallFailsWithErrno(EINVAL));
}

// Testing that simple mmap call succeeds.
TEST(IoUringTest, MMapWorks) {
  struct io_uring_params params;
  memset(&params, 0, sizeof(params));
  int iouringfd = IoUringSetup(1, &params);

  void *ptr = nullptr;
  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
  if (sring_sz == 0) sring_sz = 4096;

  ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
             iouringfd, IORING_OFF_SQ_RING);

  EXPECT_NE(ptr, MAP_FAILED);
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
