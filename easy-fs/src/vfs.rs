use super::{
    BlockDevice,
    DiskInode,
    DiskInodeType,
    DirEntry,
    EasyFileSystem,
    DIRENT_SZ,
    get_block_cache,
    block_cache_sync_all,
};
use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use spin::{Mutex, MutexGuard};
use crate::BLOCK_SZ;

/// Virtual filesystem layer over easy-fs
pub struct Inode {
    pub inode: usize,
    block_id: usize,
    block_offset: usize,
    fs: Arc<Mutex<EasyFileSystem>>,
    block_device: Arc<dyn BlockDevice>,
}

impl Inode {
    /// Create a vfs inode
    pub fn new(
        inode: u32,
        block_id: u32,
        block_offset: usize,
        fs: Arc<Mutex<EasyFileSystem>>,
        block_device: Arc<dyn BlockDevice>,
    ) -> Self {
        Self {
            inode: inode as usize,
            block_id: block_id as usize,
            block_offset,
            fs,
            block_device,
        }
    }
    /// Call a function over a disk inode to read it
    fn read_disk_inode<V>(&self, f: impl FnOnce(&DiskInode) -> V) -> V {
        get_block_cache(
            self.block_id,
            Arc::clone(&self.block_device)
        ).lock().read(self.block_offset, f)
    }
    /// Call a function over a disk inode to modify it
    fn modify_disk_inode<V>(&self, f: impl FnOnce(&mut DiskInode) -> V) -> V {
        get_block_cache(
            self.block_id,
            Arc::clone(&self.block_device)
        ).lock().modify(self.block_offset, f)
    }
    /// Find inode under a disk inode by name
    fn find_inode_id(
        &self,
        name: &str,
        disk_inode: &DiskInode,
    ) -> Option<u32> {
        // assert it is a directory
        assert!(disk_inode.is_dir());
        let file_count = (disk_inode.size as usize) / DIRENT_SZ;
        let mut dirent = DirEntry::empty();
        for i in 0..file_count {
            assert_eq!(
                disk_inode.read_at(
                    DIRENT_SZ * i,
                    dirent.as_bytes_mut(),
                    &self.block_device,
                ),
                DIRENT_SZ,
            );
            if dirent.name() == name {
                return Some(dirent.inode_number() as u32);
            }
        }
        None
    }

    fn find_name_pos(
        &self,
        name: &str,
        disk_inode: &DiskInode,
    ) -> Option<usize> {
        // assert it is a directory
        assert!(disk_inode.is_dir());
        let file_count = (disk_inode.size as usize) / DIRENT_SZ;
        let mut dirent = DirEntry::empty();
        for i in 0..file_count {
            assert_eq!(
                disk_inode.read_at(
                    DIRENT_SZ * i,
                    dirent.as_bytes_mut(),
                    &self.block_device,
                ),
                DIRENT_SZ,
            );
            if dirent.name() == name {
                return Some(i);
            }
        }
        None
    }

    /// Find inode under current inode by name
    pub fn find(&self, name: &str) -> Option<Arc<Inode>> {
        let fs = self.fs.lock();
        self.read_disk_inode(|disk_inode| {
            self.find_inode_id(name, disk_inode)
            .map(|inode_id| {
                let (block_id, block_offset) = fs.get_disk_inode_pos(inode_id);
                Arc::new(Self::new(
                    inode_id,
                    block_id,
                    block_offset,
                    self.fs.clone(),
                    self.block_device.clone(),
                ))
            })
        })
    }
    /// Increase the size of a disk inode
    fn increase_size(
        &self,
        new_size: u32,
        disk_inode: &mut DiskInode,
        fs: &mut MutexGuard<EasyFileSystem>,
    ) {
        if new_size < disk_inode.size {
            return;
        }
        let blocks_needed = disk_inode.blocks_num_needed(new_size);
        let mut v: Vec<u32> = Vec::new();
        for _ in 0..blocks_needed {
            v.push(fs.alloc_data());
        }
        disk_inode.increase_size(new_size, v, &self.block_device);
    }

    fn decrease_size(
        &self,
        new_size: u32,
        disk_inode: &mut DiskInode,
        fs: &mut MutexGuard<EasyFileSystem>,
    ) {
        if new_size >= disk_inode.size {
            return;
        }
        let old_blocks = DiskInode::total_blocks(disk_inode.size);
        let blocks_after_decrease = DiskInode::total_blocks(new_size);
        disk_inode.size = new_size;

        if blocks_after_decrease >= old_blocks{
            return;
        }

        let blocks_dealloc = disk_inode.decrease_blocks(new_size as usize, &self.block_device);

        for block in blocks_dealloc{
            fs.dealloc_data(block);
        }
    }

    /// Create inode under current inode by name
    pub fn create(&self, name: &str) -> Option<Arc<Inode>> {
        let mut fs = self.fs.lock();
        if self.modify_disk_inode(|root_inode| {
            // assert it is a directory
            assert!(root_inode.is_dir());
            // has the file been created?
            self.find_inode_id(name, root_inode)
        }).is_some() {
            return None;
        }
        // create a new file
        // alloc a inode with an indirect block
        let new_inode_id = fs.alloc_inode();
        // initialize inode
        let (new_inode_block_id, new_inode_block_offset) 
            = fs.get_disk_inode_pos(new_inode_id);
        get_block_cache(
            new_inode_block_id as usize,
            Arc::clone(&self.block_device)
        ).lock().modify(new_inode_block_offset, |new_inode: &mut DiskInode| {
            new_inode.initialize(DiskInodeType::File);
        });
        self.modify_disk_inode(|root_inode| {
            // append file in the dirent
            let file_count = (root_inode.size as usize) / DIRENT_SZ;
            let new_size = (file_count + 1) * DIRENT_SZ;
            // increase size
            self.increase_size(new_size as u32, root_inode, &mut fs);
            // write dirent
            let dirent = DirEntry::new(name, new_inode_id);
            root_inode.write_at(
                file_count * DIRENT_SZ,
                dirent.as_bytes(),
                &self.block_device,
            );
        });

        let (block_id, block_offset) = fs.get_disk_inode_pos(new_inode_id);
        block_cache_sync_all();
        // return inode
        Some(Arc::new(Self::new(
            new_inode_id,
            block_id,
            block_offset,
            self.fs.clone(),
            self.block_device.clone(),
        )))
        // release efs lock automatically by compiler
    }
    /// List inodes under current inode
    pub fn ls(&self) -> Vec<String> {
        let _fs = self.fs.lock();
        self.read_disk_inode(|disk_inode| {
            let file_count = (disk_inode.size as usize) / DIRENT_SZ;
            let mut v: Vec<String> = Vec::new();
            for i in 0..file_count {
                let mut dirent = DirEntry::empty();
                assert_eq!(
                    disk_inode.read_at(
                        i * DIRENT_SZ,
                        dirent.as_bytes_mut(),
                        &self.block_device,
                    ),
                    DIRENT_SZ,
                );
                v.push(String::from(dirent.name()));
            }
            v
        })
    }
    /// Read data from current inode
    pub fn read_at(&self, offset: usize, buf: &mut [u8]) -> usize {
        let _fs = self.fs.lock();
        self.read_disk_inode(|disk_inode| {
            disk_inode.read_at(offset, buf, &self.block_device)
        })
    }
    /// Write data to current inode
    pub fn write_at(&self, offset: usize, buf: &[u8]) -> usize {
        let mut fs = self.fs.lock();
        let size = self.modify_disk_inode(|disk_inode| {
            self.increase_size((offset + buf.len()) as u32, disk_inode, &mut fs);
            disk_inode.write_at(offset, buf, &self.block_device)
        });
        block_cache_sync_all();
        size
    }
    /// Clear the data in current inode
    pub fn clear(&self) {
        let mut fs = self.fs.lock();
        self.modify_disk_inode(|disk_inode| {
            let size = disk_inode.size;
            let data_blocks_dealloc = disk_inode.clear_size(&self.block_device);
            assert!(data_blocks_dealloc.len() == DiskInode::total_blocks(size) as usize);
            for data_block in data_blocks_dealloc.into_iter() {
                fs.dealloc_data(data_block);
            }
        });
        block_cache_sync_all();
    }

    pub fn clear_data(&self) -> Vec<u32> {
        let mut data_blocks_dealloc = vec![];
        let mut fs = self.fs.lock();

        self.modify_disk_inode(|disk_inode| {
            let size = disk_inode.size;
            data_blocks_dealloc = disk_inode.decrease_blocks(0, &self.block_device);
            assert!(data_blocks_dealloc.len() == DiskInode::total_blocks(size) as usize);
            for data_block in data_blocks_dealloc.iter() {
                fs.dealloc_data(*data_block);
            }
        });
        block_cache_sync_all();
        data_blocks_dealloc
    }

    pub fn link(&self, old_path: &str, new_path: &str) -> isize{
        let mut fs = self.fs.lock();
        let old_inode = self.read_disk_inode(|disk_inode| {
            self.find_inode_id(old_path, disk_inode)
        });

        let old_inode = if old_inode.is_some(){
            old_inode.unwrap()
        }else{
            return -1;
        };

        let (block_id, block_offset) = fs.get_disk_inode_pos(old_inode);
        let old_inode = Arc::new(Self::new(
            old_inode,
            block_id,
            block_offset,
            self.fs.clone(),
            self.block_device.clone(),
        ));

        old_inode.modify_disk_inode(|disk_inode|{
            disk_inode.nlink += 1;
        });

        self.modify_disk_inode(|disk_indoe|{
            let file_count = (disk_indoe.size as usize) / DIRENT_SZ;
            let new_size = (file_count + 1) * DIRENT_SZ;
            self.increase_size(new_size as u32, disk_indoe, &mut fs);
            let dirent = DirEntry::new(new_path, old_inode.inode as u32);
            disk_indoe.write_at(
                file_count * DIRENT_SZ,
                dirent.as_bytes(),
                &self.block_device,
            );
        });

        block_cache_sync_all();
        return 0;
    }

    pub fn unlink(&self, name: &str) -> isize{
        let mut fs = self.fs.lock();
        let unlink_inode = self.read_disk_inode(|disk_inode| {
            self.find_inode_id(name, disk_inode)
        });

        let unlink_inode = if unlink_inode.is_some(){
            unlink_inode.unwrap()
        }else{
            return -1;
        };

        let name_pos = self.read_disk_inode(|disk_inode|{
            self.find_name_pos(name, disk_inode)
        });

        let name_pos = name_pos.unwrap();
        let (block_id, block_offset) = fs.get_disk_inode_pos(unlink_inode);
        let unlink_inode = Arc::new(Self::new(
            unlink_inode,
            block_id,
            block_offset,
            self.fs.clone(),
            self.block_device.clone(),
        ));

        unlink_inode.modify_disk_inode(|disk_inode|{
            disk_inode.nlink -= 1;
        });

        let should_delete_file = unlink_inode.read_disk_inode(|disk_inode|{
            disk_inode.nlink == 0
        });

        if should_delete_file{
            unlink_inode.modify_disk_inode(|disk_inode| {
                let data_blocks_dealloc = disk_inode.clear_size(&self.block_device);
                for data_block in data_blocks_dealloc.into_iter() {
                    fs.dealloc_data(data_block);
                }
            });

            fs.dealloc_inode(unlink_inode.inode);
        }

        self.modify_disk_inode(|disk_inode| {
            let file_count = (disk_inode.size as usize) / DIRENT_SZ;
            assert!(file_count > 0);

            let mut last = DirEntry::empty();
            disk_inode.read_at((file_count - 1) * DIRENT_SZ, last.as_bytes_mut(), &self.block_device);
            disk_inode.write_at(name_pos * DIRENT_SZ, last.as_bytes(), &self.block_device);
            self.decrease_size(disk_inode.size - DIRENT_SZ as u32, disk_inode, &mut fs);
        });

        block_cache_sync_all();
        return 0;
    }

    pub fn stat(&self) -> Result<(u64, usize, DiskInodeType, u32), isize>{
        self.read_disk_inode(|disk_inode|{
            let dev = 0u64;
            let ino = self.inode;
            let mode = if disk_inode.is_dir(){
                DiskInodeType::Directory
            }else{
                DiskInodeType::File
            };
            let nlink = disk_inode.nlink;
            Ok((dev, ino, mode, nlink))
        })
    }
}
