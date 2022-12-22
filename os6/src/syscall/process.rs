//! Process management syscalls

use crate::mm::{translated_refmut, translated_ref, translated_str};
use crate::task::{
    add_task, current_task, current_user_token, exit_current_and_run_next,
    suspend_current_and_run_next, TaskStatus,
};
use crate::fs::{open_file, OpenFlags};
use crate::timer::get_time_us;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::config::MAX_SYSCALL_NUM;
use alloc::string::String;
use crate::task::{TaskControlBlock};
use core::mem::size_of;
use crate::mm::kernel_copy_to_user;
use crate::mm::{VirtAddr, MapPermission, VPNRange, MapType, MapArea};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub status: TaskStatus,
    pub syscall_times: [u32; MAX_SYSCALL_NUM],
    pub time: usize,
}

pub fn sys_exit(exit_code: i32) -> ! {
    debug!("[kernel] Application exited with code {}", exit_code);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    current_task().unwrap().pid.0 as isize
}

/// Syscall Fork which returns 0 for child process and child_pid for parent process
pub fn sys_fork() -> isize {
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

/// Syscall Exec which accepts the elf path
pub fn sys_exec(path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task().unwrap();
        task.exec(all_data.as_slice());
        0
    } else {
        -1
    }
}


/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    let task = current_task().unwrap();
    // find a child process

    // ---- access current TCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB lock exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after removing from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child TCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB lock automatically
}

// YOUR JOB: 引入虚地址后重写 sys_get_time
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    let us = get_time_us();
    let tm = TimeVal{
        sec: us / 1_000_000,
        usec: us % 1_000_000
    };

    let tm_ptr = unsafe{
        core::mem::transmute::<&TimeVal, *const u8>(&tm)
    };

    let ts_ptr = unsafe{core::mem::transmute::<*mut TimeVal, *mut u8>(ts)};

    kernel_copy_to_user(tm_ptr, current_user_token(), ts_ptr, size_of::<TimeVal>());
    0
}


// YOUR JOB: 引入虚地址后重写 sys_task_info
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    let task_info = task_info_in_current();

    let task_info_ptr = unsafe{
        core::mem::transmute::<&TaskInfo, *const u8>(&task_info)
    };

    let ti_ptr = unsafe{
        core::mem::transmute::<*mut TaskInfo, *mut u8>(ti)
    };

    kernel_copy_to_user(task_info_ptr, current_user_token(), ti_ptr, size_of::<TaskInfo>());
    0
}

pub fn task_info_in_current() -> TaskInfo{
    let current = current_task().unwrap();
    current.get_task_task_info()
}

// YOUR JOB: 实现sys_set_priority，为任务添加优先级
pub fn sys_set_priority(prio: isize) -> isize {
    let prio = if prio < 2{
        return -1;
    }else{
        prio as usize
    };

    let current = current_task().unwrap();
    let mut current_inner = current.inner_exclusive_access();
    current_inner.priority = prio;
    prio as isize
}

// YOUR JOB: 扩展内核以实现 sys_mmap 和 sys_munmap
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    let v_start = VirtAddr::from(start);

    if !v_start.aligned(){
        return -1;
    }

    if (port & !0x7 != 0) || (port &0x7 == 0){
        return -1;
    }

    let mut map_permit = MapPermission::empty();
    map_permit |= MapPermission::U;

    if (port & 0x01) != 0{
        map_permit |= MapPermission::R;
    }

    if (port & 0x02) != 0{
        map_permit |= MapPermission::W;
    }

    if (port & 0x04) != 0{
        map_permit |= MapPermission::X;
    }

    let v_end = VirtAddr::from(start + len);
    let vpn_start = v_start.floor();
    let vpn_end = v_end.ceil();
    let map_range = VPNRange::new(vpn_start, vpn_end);

    if any_vpn_mapped_in_current(map_range){
        return -1;
    }

    map_in_current(v_start, v_end, map_permit);
    0
}

pub fn any_vpn_mapped_in_current(vpn_range: VPNRange) -> bool{
    let current = current_task().unwrap();
    let current_inner = current.inner_exclusive_access();
    current_inner.memory_set.any_vpn_mapped(vpn_range)
}

pub fn map_in_current(va_start: VirtAddr, va_end: VirtAddr, permit: MapPermission){
    let current = current_task().unwrap();
    let mut current_inner = current.inner_exclusive_access();
    current_inner.memory_set.push(MapArea::new(va_start, va_end, MapType::Framed, permit), None)
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    let start_va = VirtAddr::from(start);

    if !start_va.aligned(){
        return -1;
    }

    let start_vpn = start_va.floor();
    let end_va = VirtAddr::from(start + len);
    let end_vpn = end_va.ceil();

    if !all_vpn_mapped_in_current(VPNRange::new(start_vpn, end_vpn)){
        return -1;
    }

    unmap_in_current(VPNRange::new(start_vpn, end_vpn));
    0
}

pub fn all_vpn_mapped_in_current(vpn_range: VPNRange) -> bool{
    let current = current_task().unwrap();
    let current_inner = current.inner_exclusive_access();
    current_inner.memory_set.all_vpn_mapped(vpn_range)
}

pub fn unmap_in_current(vpn_range: VPNRange){
    let current = current_task().unwrap();
    let mut current_inner = current.inner_exclusive_access();
    current_inner.memory_set.pop(vpn_range);
}

//
// YOUR JOB: 实现 sys_spawn 系统调用
// ALERT: 注意在实现 SPAWN 时不需要复制父进程地址空间，SPAWN != FORK + EXEC 
pub fn sys_spawn(path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);

    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let current_task = current_task().unwrap();
        let new_task = current_task.spawn(data);
        let new_pid = new_task.pid.0;
        add_task(new_task);
        new_pid as isize
    } else {
        -1
    }
}

pub fn increase_task_syscall_count(syscall_id: usize){
    let current = current_task().unwrap();
    let mut current_inner = current.inner_exclusive_access();
    current_inner.increase_task_syscall_count(syscall_id);
}