//! ReFS 3.14 read-only raw metadata scanner.
//!
//! librefs is used for the real boot-sector/checksum and standard-information
//! decoding. Its 0.1 B+tree API uses a simplified row layout, so the bounded tree
//! walker below follows the actual ReFS v3 on-disk layout instead. No USN API or
//! recursive filesystem enumeration is used to discover file names.
//! Structure reference: libyal/libfsrefs ReFS format documentation. This is an
//! independent, bounds-checked Rust implementation, not a copy of its C sources.
use anyhow::{Context,Result,bail,ensure};
use ahash::{AHashMap,AHashSet};
use std::{collections::VecDeque,sync::{Arc,Condvar,Mutex,atomic::{AtomicU64,Ordering},mpsc}};
use crate::{model::{Snapshot,DIR,REPARSE,HARDLINK,INCOMPLETE},platform::{self,RawReader,VolumeInfo}};

fn u16at(b:&[u8],at:usize)->Result<u16>{Ok(u16::from_le_bytes(b.get(at..at+2).context("truncated ReFS u16")?.try_into()?))}
fn u32at(b:&[u8],at:usize)->Result<u32>{Ok(u32::from_le_bytes(b.get(at..at+4).context("truncated ReFS u32")?.try_into()?))}
fn u64at(b:&[u8],at:usize)->Result<u64>{Ok(u64::from_le_bytes(b.get(at..at+8).context("truncated ReFS u64")?.try_into()?))}
fn idat(b:&[u8],at:usize)->Result<[u8;16]>{Ok(b.get(at..at+16).context("truncated ReFS 128-bit ID")?.try_into()?)}
fn directory_id(low:u64)->[u8;16]{let mut id=[0;16];id[8..].copy_from_slice(&low.to_le_bytes());id}
#[derive(Clone,Copy,Debug)]struct BlockRef{lcns:[u64;4],kind:u8,hash:[u8;8]}
impl BlockRef{
    fn parse(b:&[u8])->Result<Self>{ensure!(b.len()>=48,"short ReFS block reference");let mut lcns=[0;4];for(i,n)in lcns.iter_mut().enumerate(){*n=u64at(b,i*8)?;}ensure!(lcns[0]!=0,"empty ReFS block reference");
        let kind=b[34];ensure!(b[35]==8&&((kind==1&&u16at(b,36)?==4)||(kind==2&&u16at(b,36)?==8)),"unsupported ReFS block checksum descriptor");Ok(Self{lcns,kind,hash:b[40..48].try_into()?})
    }
}
#[derive(Debug)]struct Row<'a>{key:&'a[u8],value:&'a[u8]}
#[derive(Debug)]struct Node<'a>{branch:bool,rows:Vec<Row<'a>>}
fn node(b:&[u8],base:usize)->Result<Node<'_>>{
    let at=base.checked_add(u32at(b,base)? as usize).context("node offset overflow")?;
    ensure!(at>=base+4&&at+32<=b.len(),"ReFS node header outside metadata page");
    let branch=b[at+13]&1!=0;let count=u32at(b,at+20)? as usize;
    let array=at.checked_add(u32at(b,at+16)? as usize).context("slot array overflow")?;
    ensure!(count<=b.len()/4&&array>=at+32&&array.checked_add(count*4).is_some_and(|end|end<=b.len()),"ReFS node slot array outside page");
    let mut rows=Vec::with_capacity(count);
    for i in 0..count{
        let offset=(u32at(b,array+i*4)?&0xffff) as usize;let start=at.checked_add(offset).context("row offset overflow")?;
        let length=u32at(b,start)? as usize;ensure!(length>=16&&start.checked_add(length).is_some_and(|end|end<=b.len()),"invalid ReFS row length");let row=&b[start..start+length];
        let flags=u16at(row,8)?;if flags&4!=0{continue;}
        let ko=u16at(row,4)? as usize;let kl=u16at(row,6)? as usize;let vo=u16at(row,10)? as usize;let vl=u32at(row,12)? as usize;
        ensure!((kl==0||ko>=16)&&(vl==0||vo>=16),"ReFS row payload overlaps header");
        let key=row.get(ko..ko.checked_add(kl).context("key length overflow")?).context("ReFS key outside row")?;
        let value=row.get(vo..vo.checked_add(vl).context("value length overflow")?).context("ReFS value outside row")?;
        rows.push(Row{key,value});
    }Ok(Node{branch,rows})
}
// ReFS CRC64 is CRC-64/NVME, NOT ECMA-182. librefs 0.1's CRC64
// polynomial/direction do not match actual ReFS 3.14 pages, so use the verified
// Rocksoft parameters here. Check: "123456789" -> AE8B14860A799888.
const fn crc64_tables()->[[u64;256];8]{
    let mut table=[[0;256];8];let mut i=0;while i<256{let mut c=i as u64;let mut bit=0;while bit<8{c=if c&1!=0{(c>>1)^0x9a6c9329ac4bc9b5}else{c>>1};bit+=1;}table[0][i]=c;i+=1;}
    let mut s=1;while s<8{let mut i=0;while i<256{let c=table[s-1][i];table[s][i]=(c>>8)^table[0][(c&255) as usize];i+=1;}s+=1;}table
}
const CRC64:[[u64;256];8]=crc64_tables();
fn crc64(data:&[u8])->u64{
    let mut c=u64::MAX;let mut chunks=data.chunks_exact(8);
    for chunk in &mut chunks{let x=c^u64::from_le_bytes(chunk.try_into().unwrap());
        c=CRC64[7][(x&255)as usize]^CRC64[6][((x>>8)&255)as usize]^CRC64[5][((x>>16)&255)as usize]^CRC64[4][((x>>24)&255)as usize]
         ^CRC64[3][((x>>32)&255)as usize]^CRC64[2][((x>>40)&255)as usize]^CRC64[1][((x>>48)&255)as usize]^CRC64[0][(x>>56)as usize];}
    for &b in chunks.remainder(){c=(c>>8)^CRC64[0][((c as u8)^b)as usize];}
    let c=c^u64::MAX;if c==0xabbaffffabbafffe{0xabbaffffabbaffff}else{c}
}

fn verify_self(page:&[u8],offset:usize,length:usize,cluster:usize)->Result<()>{
    ensure!(length==48&&offset+length<=cluster&&cluster<=page.len(),"unsupported ReFS self-checksum descriptor");
    let reference=BlockRef::parse(&page[offset..offset+length])?;let mut bytes=page[..cluster].to_vec();bytes[offset..offset+length].fill(0);
    match reference.kind{1=>ensure!(librefs::checksum::crc32c(&bytes)==u32::from_le_bytes(reference.hash[..4].try_into()?),"ReFS anchor CRC32C mismatch"),2=>ensure!(crc64(&bytes)==u64::from_le_bytes(reference.hash),"ReFS anchor CRC64 mismatch"),_=>bail!("unsupported ReFS anchor checksum")}
    Ok(())
}

struct Metadata{
    raw:RawReader,cluster:u64,containers:AHashMap<u64,u64>,container_clusters:u64,
    objects:AHashMap<[u8;16],BlockRef>,bytes_read:AtomicU64,checkpoint:u64,
}
impl Metadata{
    fn read(&self,offset:u64,bytes:&mut[u8])->Result<()>{self.read_from(&self.raw,offset,bytes)}
    fn read_from(&self,raw:&RawReader,offset:u64,bytes:&mut[u8])->Result<()>{raw.read_exact_at(offset,bytes)?;self.bytes_read.fetch_add(bytes.len() as u64,Ordering::Relaxed);Ok(())}
    fn translate(&self,lcn:u64)->Result<u64>{let shift=self.container_clusters.trailing_zeros()+1;let container=lcn>>shift;let base=self.containers.get(&container).with_context(||format!("unmapped ReFS container {container:x}"))?;base.checked_add(lcn&(self.container_clusters-1)).context("physical ReFS LCN overflow")}
    fn page(&self,raw:&RawReader,reference:BlockRef,physical:bool)->Result<Vec<u8>>{
        let count=reference.lcns.iter().take_while(|&&lcn|lcn!=0).count();ensure!(reference.lcns[count..].iter().all(|&v|v==0),"non-contiguous block-reference slots");let mut lcns=Vec::with_capacity(count);
        for &n in &reference.lcns[..count]{lcns.push(if physical{n}else{self.translate(n)?});}
        let mut buf=vec![0u8;self.cluster as usize*count];ensure!((4096..=262144).contains(&buf.len()),"unsupported ReFS metadata page length");
        if lcns.windows(2).all(|p|p[1]==p[0]+1){self.read_from(raw,lcns[0].checked_mul(self.cluster).context("physical offset overflow")?,&mut buf)?;}else{for(i,&lcn)in lcns.iter().enumerate(){self.read_from(raw,lcn.checked_mul(self.cluster).context("physical offset overflow")?,&mut buf[i*self.cluster as usize..(i+1)*self.cluster as usize])?;}}
        ensure!(buf.get(..4)==Some(b"MSB+"),"invalid ReFS metadata signature at {:x?}",reference.lcns);
        for i in 0..4{ensure!(u64at(&buf,32+i*8)?==reference.lcns[i],"ReFS page identity changed or mismatched");}
        match reference.kind{1=>ensure!(librefs::checksum::crc32c(&buf)==u32::from_le_bytes(reference.hash[..4].try_into()?),"ReFS page CRC32C mismatch"),2=>ensure!(crc64(&buf)==u64::from_le_bytes(reference.hash),"ReFS page CRC64 mismatch at {:x?}",reference.lcns),_=>bail!("unsupported ReFS page checksum")}
        Ok(buf)
    }
    fn walk(&self,root:BlockRef,physical:bool,visit:impl FnMut(Row<'_>)->Result<()>)->Result<()>{self.walk_from(&self.raw,root,physical,visit)}
    fn walk_from(&self,raw:&RawReader,root:BlockRef,physical:bool,mut visit:impl FnMut(Row<'_>)->Result<()>)->Result<()>{
        let mut stack=vec![(root,0u8)];let mut seen=AHashSet::new();
        while let Some((reference,depth))=stack.pop(){ensure!(depth<=32,"ReFS metadata B+tree too deep");ensure!(seen.insert(reference.lcns),"cycle/duplicate page in ReFS B+tree");ensure!(seen.len()<=4_000_000,"excessive ReFS metadata tree");
            let page=self.page(raw,reference,physical)?;let n=node(&page,0x50)?;
            if n.branch{for r in n.rows.into_iter().rev(){stack.push((BlockRef::parse(r.value)?,depth+1));}}
            else{for row in n.rows{visit(row)?;}}
        }Ok(())
    }
    fn open(volume:&VolumeInfo)->Result<Self>{
        let raw=RawReader::volume(volume)?;let mut boot=[0;512];raw.read_exact_at(0,&mut boot)?;let boot=librefs::boot::BootSector::parse(&boot).context("librefs boot sector")?;
        // v3.14 is the format exercised on this Windows 11 Dev Drive. Fail closed
        // on other versions instead of treating invented layouts as a fast scan.
        ensure!(boot.version_major()==3&&boot.version_minor()==14,"raw ReFS backend currently validated only for 3.14, detected {}.{}; use explicit --backend fs",boot.version_major(),boot.version_minor());
        let cluster=boot.cluster_size();ensure!(cluster==4096,"raw ReFS 3.14 scan is currently validated for 4KiB clusters; detected {cluster}; use explicit --backend fs for other layouts");
        let mut meta=Self{raw,cluster,containers:AHashMap::new(),container_clusters:0,objects:AHashMap::new(),bytes_read:AtomicU64::new(512),checkpoint:0};
        let mut boot_bytes=[0;512];meta.read(0,&mut boot_bytes)?;boot.verify_checksum(&boot_bytes).context("librefs boot checksum")?;
        let mut sup=vec![0;cluster.max(16384) as usize];meta.read(30*cluster,&mut sup)?;ensure!(sup.get(..4)==Some(b"SUPB"),"ReFS superblock signature missing");
        verify_self(&sup,u32at(&sup,0x78)? as usize,u32at(&sup,0x7c)? as usize,cluster as usize)?;
        let array=u32at(&sup,0x70)? as usize;let count=u32at(&sup,0x74)? as usize;ensure!(count==2&&array+count*8<=sup.len(),"unsupported ReFS checkpoint reference table");
        let mut checkpoints=Vec::new();for i in 0..count{let mut page=vec![0;cluster.max(16384) as usize];let lcn=u64at(&sup,array+i*8)?;if meta.read(lcn.checked_mul(cluster).context("checkpoint offset overflow")?,&mut page).is_ok()&&page.get(..4)==Some(b"CHKP")&&verify_self(&page,u32at(&page,0x58)? as usize,u32at(&page,0x5c)? as usize,cluster as usize).is_ok(){checkpoints.push(page);}}
        checkpoints.sort_by_key(|page|std::cmp::Reverse(u64at(page,0x60).unwrap_or(0)));
        let cp=checkpoints.first().context("no readable ReFS checkpoint")?;meta.checkpoint=u64at(cp,0x60)?;
        let n=u32at(cp,0x90)? as usize;let offset=u32at(cp,0x94)? as usize;ensure!((8..=64).contains(&n)&&offset+n*4<=cp.len(),"unsupported ReFS checkpoint root array");
        let mut roots=Vec::new();for i in 0..n{let at=u32at(cp,offset+i*4)? as usize;roots.push(BlockRef::parse(cp.get(at..at+48).context("checkpoint table root out of bounds")?)?);}
        let mut containers=AHashMap::new();let mut cpc=0;
        meta.walk(roots[7],true,|r|{ensure!(r.key.len()==16&&r.value.len()>=160,"unsupported ReFS container row");let size=u64at(r.value,152)?;ensure!(size.is_power_of_two()&&size>=16,"invalid ReFS container size");ensure!(cpc==0||cpc==size,"mixed ReFS container geometries unsupported");cpc=size;let key=u64at(r.key,0)?;let physical=u64at(r.value,144)?;ensure!(containers.insert(key,physical).is_none(),"duplicate ReFS container ID");Ok(())})?;
        ensure!(cpc>0&&!containers.is_empty(),"empty ReFS container map");meta.container_clusters=cpc;meta.containers=containers;
        let mut objects=AHashMap::new();meta.walk(roots[0],false,|r|{ensure!(r.key.len()==16&&r.value.len()>=80,"unsupported ReFS object-table row");let id=idat(r.key,0)?;ensure!(objects.insert(id,BlockRef::parse(&r.value[32..80])?).is_none(),"duplicate ReFS object ID");Ok(())})?;
        ensure!(objects.contains_key(&directory_id(0x600)),"ReFS root directory object missing");meta.objects=objects;Ok(meta)
    }
}
#[derive(Debug)]struct Entry{name:Vec<u16>,object:[u8;16],logical:u64,allocated:u64,mtime:Option<i64>,flags:u16,kernel_check:bool}
fn has_named_stream(value:&[u8])->Result<bool>{let n=node(value,0)?;if n.branch{return Ok(true);}Ok(n.rows.iter().any(|r|r.key.len()>=16&&u16at(r.key,12).is_ok_and(|t|t==0xb0)))}
fn entry(row:Row<'_>,parent_object:[u8;16])->Result<Option<Entry>>{
    if row.key.len()<4||u16at(row.key,0)?!=0x30{return Ok(None);}ensure!((row.key.len()-4)%2==0,"odd UTF-16 filename length");
    let name:Vec<u16>=row.key[4..].chunks_exact(2).map(|p|u16::from_le_bytes([p[0],p[1]])).collect();
    ensure!(!name.is_empty()&&!name.contains(&0)&&!name.contains(&47)&&!name.contains(&92),"invalid ReFS filename component");
    let kind=u16at(row.key,2)?;
    match kind{
        2=>{
            ensure!(row.value.len()>=72,"short ReFS directory/hardlink entry");let object=idat(row.value,0)?;let file_id=u64at(row.value,0)?;let attrs=u32at(row.value,64)?;
            let directory=file_id==0;ensure!(directory==(attrs&0x10000000!=0),"unknown ReFS short-entry object type");
            let flags=if directory{DIR}else{HARDLINK}|if attrs&0x400!=0{REPARSE}else{0};
            Ok(Some(Entry{name,object,logical:u64at(row.value,48)?,allocated:u64at(row.value,56)?,mtime:platform::modified_unix_ms(u64at(row.value,24)? as i64),flags,kernel_check:!directory}))
        },
        1=>{
            let base=u16at(row.value,4)? as usize;let end=u32at(row.value,0)? as usize;ensure!(base>=8&&end>=base+128&&end<=row.value.len(),"invalid ReFS standard information bounds");
            let si=librefs::metadata::StandardInformation::parse(&row.value[base..end]).context("librefs standard information")?;
            let mut object=parent_object;object[..8].copy_from_slice(&si.object_id[..8]);
            let flags=if si.attributes.0&0x400!=0{REPARSE}else{0};
            Ok(Some(Entry{name,object,logical:si.end_of_file,allocated:si.allocation_size,mtime:platform::modified_unix_ms(si.last_write_time.get() as i64),flags,kernel_check:has_named_stream(row.value)?}))
        },
        other=>bail!("unsupported ReFS file-entry kind {other}; not dropping it silently"),
    }
}
struct Job{parent:u32,object:[u8;16]}
struct Queue{jobs:VecDeque<Job>,closed:bool}
enum Message{Batch(u32,Vec<Entry>),Error(String),Done}

pub fn scan(volume:&VolumeInfo,threads:usize,memory_limit:u64)->Result<Snapshot>{
    #[cfg(not(windows))]bail!("raw ReFS scanning requires Windows");
    #[cfg(windows)]{
        let meta=Metadata::open(volume)?;
        let readers=(0..threads).map(|_|RawReader::volume(volume)).collect::<Result<Vec<_>>>()?;
        let mut s=Snapshot::new(volume.root.clone(),volume.clone(),"refs-raw-btree+librefs",threads);
        let shared=Arc::new((Mutex::new(Queue{jobs:VecDeque::from([Job{parent:0,object:directory_id(0x600)}]),closed:false}),Condvar::new()));
        let(tx,rx)=mpsc::sync_channel::<Message>(threads*2);let mut directories=AHashSet::from_iter([directory_id(0x600)]);let mut hardlinks=AHashSet::new();let mut verified=0u64;
        std::thread::scope(|scope|->Result<()>{
            for raw in readers{let tx=tx.clone();let shared=shared.clone();let meta=&meta;scope.spawn(move||{
                loop{let job={let(lock,cv)=&*shared;let mut q=lock.lock().unwrap();while q.jobs.is_empty()&&!q.closed{q=cv.wait(q).unwrap();}if q.closed{return;}q.jobs.pop_front().unwrap()};
                    let result=(||->Result<()>{let reference=*meta.objects.get(&job.object).context("ReFS directory not in object table")?;let mut batch=Vec::with_capacity(256);
                        meta.walk_from(&raw,reference,false,|row|{if let Some(entry)=entry(row,job.object)?{batch.push(entry);if batch.len()==256{tx.send(Message::Batch(job.parent,std::mem::replace(&mut batch,Vec::with_capacity(256)))).context("scan cancelled")?;}}Ok(())})?;
                        if !batch.is_empty(){tx.send(Message::Batch(job.parent,batch)).context("scan cancelled")?;}Ok(())})();
                    if let Err(e)=result{if tx.send(Message::Error(format!("ReFS directory {:x?}: {e:#}",job.object))).is_err(){return;}}
                    if tx.send(Message::Done).is_err(){return;}
                }
            });}
            drop(tx);
            let consume=(||->Result<()>{let mut pending=1;
                while pending>0{match rx.recv().context("ReFS workers stopped")?{
                    Message::Batch(parent,entries)=>{let mut jobs=Vec::new();for mut e in entries{
                        let path=s.path(parent).join(platform::decode_name(&e.name));
                        if e.kernel_check{
                            let checked=platform::identity(&path);
                            match checked{Ok(m)=>{e.logical=m.length;e.allocated=m.allocated;e.mtime=platform::modified_unix_ms(m.modified);verified+=1;},Err(error)=>{s.warn(format!("complex stream metadata {}: {error:#}",path.display()));e.flags|=INCOMPLETE;}}
                        }
                        if e.flags&HARDLINK!=0&&!hardlinks.insert(e.object){e.allocated=0;}
                        let id=s.push(parent,&e.name,e.logical,e.allocated,e.flags)?;s.set_file_mtime(id,e.mtime);s.stats.records_read+=1;
                        if e.flags&DIR!=0&&e.flags&REPARSE==0{ensure!(directories.insert(e.object),"duplicate/cyclic ReFS directory object");jobs.push(Job{parent:id,object:e.object});pending+=1;}
                    }
                    ensure!(s.index_bytes()+directories.capacity() as u64*32+meta.objects.capacity() as u64*96+meta.containers.capacity() as u64*24<=memory_limit,"ReFS index exceeds --max-memory-mib");
                    if !jobs.is_empty(){let(lock,cv)=&*shared;lock.lock().unwrap().jobs.extend(jobs);cv.notify_all();}
                    },Message::Error(e)=>s.warn(e),Message::Done=>pending-=1,
                }}Ok(())})();
            {let(lock,cv)=&*shared;lock.lock().unwrap().closed=true;cv.notify_all();}drop(rx);consume
        })?;
        s.stats.raw_bytes_read=meta.bytes_read.load(Ordering::Relaxed);
        s.stats.warnings.push(format!("ReFS 3.14 checkpoint {}: raw superblock/container/object/directory B+trees; metadata-page CRC verified. {verified} complex ADS/hardlink entries additionally checked by exact path; no filesystem name enumeration.",meta.checkpoint));
        s.stats.warnings.push("Live COW checkpoint, not a frozen volume. Reparse targets are not followed; shared/cloned blocks make allocated size an upper bound, not exclusive reclaimable space.".into());
        s.finish()?;Ok(s)
    }
}
#[cfg(test)]mod tests{
    use super::*;
    #[test]fn crc64_nvme_vector(){assert_eq!(crc64(b"123456789"),0xae8b14860a799888);}
    #[test]fn rejects_truncated_nodes_without_panics(){for n in 0..256{let b=vec![0xff;n];assert!(node(&b,0).is_err());}}
    #[test]fn root_object_is_full_128_bit_id(){let id=directory_id(0x600);assert_eq!(&id[..8],&[0;8]);assert_eq!(u64::from_le_bytes(id[8..].try_into().unwrap()),0x600);}
}
