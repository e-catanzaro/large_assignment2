use crate::{SectorIdx, SectorVec};
use sha2::Digest;
use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{read_dir, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Semaphore;

#[async_trait::async_trait]
pub trait SectorsManager: Send + Sync {
    /// Returns 4096 bytes of sector data by index.
    async fn read_data(&self, idx: SectorIdx) -> SectorVec;

    /// Returns timestamp and write rank of the process which has saved this data.
    /// Timestamps and ranks are relevant for atomic register algorithm, and are described
    /// there.
    async fn read_metadata(&self, idx: SectorIdx) -> (u64, u8);

    /// Writes a new data, along with timestamp and write rank to some sector.
    async fn write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8));
}

const SECTOR_SIZE: usize = 4096;

const MAX_OPEN_FILE : usize = 1024;


/// Path parameter points to a directory to which this method has exclusive access.
pub async fn build_sectors_manager(path: PathBuf) -> Arc<dyn SectorsManager> {
    // checking if there have been errors during the write of the files
    Arc::new(StableSectorsManager::build(path).await)
}


struct StableSectorsManager {
    root : PathBuf,
    counter : Semaphore,
}

#[async_trait::async_trait]
impl SectorsManager for StableSectorsManager {
    async fn read_data(&self, idx: SectorIdx) -> SectorVec {
        let sector_path = self.root.join(idx.to_string());
        let mut sector_data = [0u8; SECTOR_SIZE];

        if sector_path.exists() {
            self.permit_opening().await;
            let mut sector = File::open(sector_path).await.unwrap();
            sector.read_exact(&mut sector_data).await.unwrap();
        }
        SectorVec{ 0: sector_data.to_vec() }

    }

    async fn read_metadata(&self, idx: SectorIdx) -> (u64, u8) {
        let sector_path = self.root.join(idx.to_string());
        let mut timestamp : u64 = 0;
        let mut rank : u8 = 0;

        if sector_path.exists() {
            self.permit_opening().await;
            let mut file = File::open(sector_path).await.unwrap();
            file.seek(SeekFrom::Start(SECTOR_SIZE as u64)).await.unwrap();
            timestamp = file.read_u64().await.unwrap();
            rank = file.read_u8().await.unwrap();
        }
        (timestamp, rank)
    }

    async fn write(&self, idx: SectorIdx, sector: &(SectorVec, u64, u8)) {
        let sector_path = self.root.join(idx.to_string());
        let tmp_path = self.root.join("tmp_".to_string() + &idx.to_string() );

        self.permit_opening().await;
        let mut dir = File::open(&self.root).await.unwrap();
        let mut tmp_file = File::create(tmp_path.clone()).await.unwrap();
        self.permit_opening().await;
        let mut file = File::create(sector_path).await.unwrap();

        let stable_content = [sector.0.0.as_slice(), &sector.1.to_be_bytes(), &sector.2.to_be_bytes()].concat();
        let tmp_content = [sha2::Sha256::digest(&stable_content).as_slice(),&stable_content].concat();

        self.write_and_sync(&mut tmp_file, &mut dir, tmp_content.as_slice()).await;
        self.write_and_sync(&mut file, &mut dir, &stable_content).await;

        self.delete_and_sync(tmp_path, &mut dir).await;
    }
}



impl StableSectorsManager {
    async fn build(root: PathBuf) -> Self {
        let sectors_manager = StableSectorsManager {
            root: root.clone(),
            counter : Semaphore::new(MAX_OPEN_FILE),
        };

        let mut parent_dir = File::open(&root).await.unwrap();
        let mut paths = read_dir(&root).await.unwrap();

        while let Ok(Some(dir_entry)) = paths.next_entry().await{
            let file_name = dir_entry.file_name();
            let file_name =file_name.to_str().unwrap();
            if !file_name.contains("tmp"){ continue; }
            let tmp_path = root.join(file_name);

            let stable_file_name = &file_name[4..];
            sectors_manager.permit_opening().await;
            let mut tmp_file = File::open(&tmp_path).await.unwrap();
            let mut hash = [0u8;32];
            tmp_file.read_exact(&mut hash).await.unwrap_or_default();
            let mut content = [0u8; SECTOR_SIZE + 8 + 1];
            tmp_file.read_exact(&mut content).await.unwrap_or_default();

            if hash == sha2::Sha256::digest(&content).as_slice(){
                sectors_manager.permit_opening().await;
                let mut stable_file = File::create(root.join(stable_file_name)).await.unwrap();
                sectors_manager.write_and_sync(&mut stable_file, &mut parent_dir, content.as_slice()).await;
            }
            sectors_manager.delete_and_sync(root.join(&tmp_path), &mut parent_dir).await;
        }

        sectors_manager
    }

    async fn write_and_sync(&self, file : &mut File, dir : &mut File,  content_to_write : &[u8]) {
        file.write_all(&content_to_write).await.unwrap();
        file.sync_all().await.unwrap();
        dir.sync_data().await.unwrap();
    }

    async fn delete_and_sync(&self, path_to_delete : PathBuf, parent_dir : &mut File) {
        tokio::fs::remove_file(&path_to_delete).await.unwrap();
        parent_dir.sync_data().await.unwrap();
    }

    async fn permit_opening(&self){
        let _ = self.counter.acquire().await;
    }

}