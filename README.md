# cca_sec_list
Complete List of Problematic Cross-World Interfaces
This document uses the same five-column organization as the summary table in the paper: Interface, Source, Sink, Missing validation, and Type.
T1 — Confidential-data violation: a Host-controlled interface causes protected data to be exposed to, or improperly influenced by, the untrusted world.
T2 — Control-flow/state integrity violation: a Host-controlled interface causes unauthorized changes to privileged execution, protected state, or control flow.
T1/T2: the interface can lead to either effect, depending on the attacker-controlled fields and the consumer.
Summary
      System
      Interface type
      External interfaces
      Reported paths
      Confidential Containers
      VSOCK/ttrpc management RPCs
      18
      18
      TF-RMM
      RMI vCPU-entry / virtual-interrupt interface
      1
      1
      Islet
      Rust RMI vCPU-entry / virtual-interrupt interface
      1
      1
      SHELTER
      Forwarded syscall/ioctl return interfaces
      37
      37
      CAGE
      SMC/GPT GPU-task submission interface
      1
      2
      Total
      —
      58
      59
  CAGE exposes one SMC command (0xc7000008) with two distinct high-risk data-flow paths.
Case I: Confidential Containers — VSOCK/ttrpc Management RPCs
Count: 18 high-risk interfaces.
agent-policy configuration.
      Interface
      Source
      Sink
      Missing validation
      Type
      CreateContainer
      CreateContainerRequest
      runc.Create()
      Caller authentication and container-creation authorization
      T2
      StartContainer
      StartContainerRequest
      runc.Start()
      Caller authentication and lifecycle authorization
      T2
      RemoveContainer
      RemoveContainerRequest
      runc.Delete()
      Caller authentication and deletion authorization
      T2
      ExecProcess
      ExecProcessRequest
      Process::new() → ctr.run() / fork+execve
      Caller authentication and execution authorization
      T2
      SignalProcess
      SignalProcessRequest
      kill(pid, signal)
      Process ownership and signal authorization
      T2
      UpdateContainer
      UpdateContainerRequest
      runc.Update()
      Resource-policy authorization
      T2
      PauseContainer
      PauseContainerRequest
      freezer.Freeze()
      Lifecycle-state authorization
      T2
      ResumeContainer
      ResumeContainerRequest
      freezer.Thaw()
      Lifecycle-state authorization
      T2
      WriteStdin
      WriteStdinRequest
      write(stdin_fd)
      Stream ownership and access authorization
      T1
      ReadStdout
      ReadStdoutRequest
      read(stdout_fd)
      Output-stream access authorization
      T1
      CloseStdin
      CloseStdinRequest
      close(stdin_fd)
      Stream ownership and state validation
      T2
      SetIPTables
      SetIPTablesRequest
      iptables.Set()
      Network-policy authorization
      T2
      UpdateRoutes
      UpdateRoutesRequest
      netlink.RouteAdd/Del()
      Route-update authorization
      T2
      AddARPNeighbors
      AddARPNeighborsRequest
      netlink.NeighAdd()
      Neighbor-update authorization
      T2
      CreateSandbox
      CreateSandboxRequest
      Namespace and runtime setup
      Sandbox-creation authorization
      T2
      DestroySandbox
      DestroySandboxRequest
      Namespace teardown
      Sandbox-destruction authorization
      T2
      CopyFile
      CopyFileRequest
      write(guest_path)
      Realm-data access authorization
      T1
      SetGuestDateTime
      SetGuestDateTimeRequest
      clock_settime()
      Trusted-time and update authorization
      T2
Case II: TF-RMM — RMI Virtual-Interrupt Entry Path
Count: 1 high-risk interface/path.
      Interface
      Source
      Sink
      Missing validation
      Type
      RMI_REC_ENTER
      Host-programmed ICH_LR<n>_EL2, read into gic_cpu_state.ich_lr_el2[] by read_lrs()
      rec_run_loop() and subsequent virtual-interrupt delivery
      LR priority/control-field semantics
      T2
  In the analyzed TF-RMM revision, struct rmi_rec_enter contains flags and gprs[]; it does not contain rec_run.enter.gic.vlr[]. The virtual-interrupt source is the Host-programmed List Registers read by gic_validate_vgic().
Case III: Islet — Rust RMI Virtual-Interrupt Entry Path
Count: 1 high-risk interface/path.
      Interface
      Source
      Sink
      Missing validation
      Type
      RMI_REC_ENTER
      Run::Entry.gicv3_lrs[]
      restore_state()
      Trusted provenance and interrupt-state semantics
      T2
Case IV: SHELTER — Forwarded Syscall/ioctl Return Interfaces
Count: 37 high-risk interfaces.
A. Return status checked; content not semantically validated
      Interface
      Source
      Sink
      Missing validation
      Type
      ioctl(FIONREAD)
      int in task_shared_virt
      memcpy_for_shelter()
      Range and consistency
      T2
      ioctl(TIOCGSOFTCAR)
      int in task_shared_virt
      memcpy_for_shelter()
      Value semantics
      T2
      ioctl(FIGETBSZ)
      int in task_shared_virt
      memcpy_for_shelter()
      Valid block-size range
      T2
      ioctl(TCGETS)
      struct termios in task_shared_virt
      memcpy_for_shelter()
      Field and cross-field semantics
      T2
      ioctl(TCGETS2)
      struct termios2 in task_shared_virt
      memcpy_for_shelter()
      Field and cross-field semantics
      T2
      ioctl(TCGETX)
      struct termiox in task_shared_virt
      memcpy_for_shelter()
      Field and cross-field semantics
      T2
      ioctl(TCGETA)
      struct termio in task_shared_virt
      memcpy_for_shelter()
      Field and cross-field semantics
      T2
      ioctl(TIOCGLCKTRMIOS)
      Locked-termios structure in task_shared_virt
      memcpy_for_shelter()
      Field and lock-state semantics
      T2
      ioctl(FIOQSIZE)
      64-bit size in task_shared_virt
      memcpy_for_shelter()
      Range and consistency
      T2
      ioctl(FIBMAP)
      Block number in task_shared_virt
      memcpy_for_shelter()
      Range and file-map consistency
      T2
      ioctl(FS_IOC_FIEMAP)
      fiemap header/extents in task_shared_virt
      memcpy_for_shelter()
      Extent-count and extent-array consistency
      T2
      uname
      struct utsname in task_shared_virt
      memcpy_for_shelter()
      Structure semantics
      T2
      sysinfo
      struct sysinfo in task_shared_virt
      memcpy_for_shelter()
      Field ranges and consistency
      T2
      fstat
      struct stat in task_shared_virt
      memcpy_for_shelter()
      Metadata consistency
      T2
      newfstatat
      struct stat in task_shared_virt
      memcpy_for_shelter()
      Metadata consistency
      T2
      rt_sigaction
      struct sigaction in task_shared_virt
      memcpy_for_shelter()
      Handler, mask, and flag semantics
      T2
      rt_sigprocmask
      Signal set in task_shared_virt
      memcpy_for_shelter()
      Mask semantics
      T2
      prlimit64
      struct rlimit64 in task_shared_virt
      memcpy_for_shelter()
      Policy range and consistency
      T2
      getrlimit
      struct rlimit in task_shared_virt
      memcpy_for_shelter()
      Policy range and consistency
      T2
      clock_gettime
      struct timespec in task_shared_virt
      memcpy_for_shelter()
      Freshness and monotonicity
      T2
      pipe2
      File-descriptor pair in task_shared_virt
      memcpy_for_shelter()
      Descriptor identity and ownership
      T2
      gettimeofday
      timeval / timezone in task_shared_virt
      memcpy_for_shelter()
      Freshness and consistency
      T2
      socketpair
      File-descriptor pair in task_shared_virt
      memcpy_for_shelter()
      Descriptor identity and ownership
      T2
      ppoll
      pollfd.revents in task_shared_virt
      memcpy_for_shelter()
      Consistency with requested events
      T2
      pselect6
      fd_set objects in task_shared_virt
      memcpy_for_shelter()
      Consistency with submitted sets
      T2
      epoll_pwait
      epoll_event[] in task_shared_virt
      memcpy_for_shelter()
      Event/data consistency
      T2
B. Outer length checked; returned content not validated
      Interface
      Source
      Sink
      Missing validation
      Type
      read
      Byte buffer in task_shared_virt
      memcpy_for_shelter()
      Content semantics
      T2
      pread64
      Byte buffer in task_shared_virt
      memcpy_for_shelter()
      Content semantics
      T2
      readlinkat
      Path string in task_shared_virt
      memcpy_for_shelter()
      Path semantics and termination
      T2
      getrandom
      Random-byte buffer in task_shared_virt
      memcpy_for_shelter()
      Origin and entropy
      T1/T2
      recvfrom
      Payload and source address in task_shared_virt
      memcpy_for_shelter()
      Payload and peer-address semantics
      T1/T2
      getsockname
      Socket address and length in task_shared_virt
      memcpy_for_shelter()
      Address and nested length
      T2
      getpeername
      Peer address and length in task_shared_virt
      memcpy_for_shelter()
      Peer identity and nested length
      T2
      accept
      New fd, peer address, and length in task_shared_virt
      memcpy_for_shelter()
      Descriptor identity and peer semantics
      T2
      accept4
      New fd, peer address, and length in task_shared_virt
      memcpy_for_shelter()
      Descriptor identity, flags, and peer semantics
      T2
      recvmsg
      msghdr, iovecs, flags, and ancillary data in task_shared_virt
      memcpy_for_shelter()
      Nested lengths, flags, and per-iovec content
      T1/T2
      readv
      Per-iovec buffers in task_shared_virt
      memcpy_for_shelter()
      Per-iovec content and consistency
      T2
Case V: CAGE — SMC/GPT GPU-Task Submission
Count: 1 external SMC interface and 2 high-risk paths.
      Interface
      Source
      Sink
      Missing validation
      Type
      SMC 0xc7000008
      Metadata page at curtask_metadata_addr, data-buffer stub pointers, and referenced descriptors including transferred_size
      fast_memcpy_addr() and SMMUv3 Test Engine DMA
      Pointer ownership, copy bounds, and DMA range
      T1/T2
      SMC 0xc7000008
      TTBR request page at ttbr_addr, including IPA, PA, size, and attributes
      update_gpu_table()
      Mapping range, size, ownership, alignment, and attributes
      T1/T2
Interpretation Notes
The count distinguishes external interfaces from internal taint paths: CAGE has one SMC command but two sink paths.
Counts and function names correspond to the source revisions and configurations analyzed in the paper.
For Confidential Containers, the authorization result depends on the analyzed agent-policy configuration.
The T1/T2 labels follow the current paper inventory; individual exploitability may depend on configuration and the specific attacker-controlled field.