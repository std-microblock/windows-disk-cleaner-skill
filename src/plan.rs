//! Staging only. No filesystem deletion is reachable from rm or undo-rm.
use anyhow::{Context,Result,ensure};
use serde::{Serialize,Deserialize};
use std::{fs::{File,OpenOptions},io::{BufReader,BufWriter,Write},path::{Component,Path,PathBuf}};
use crate::{platform::{self,Identity},scan,model::Snapshot,git_audit::{self,GitAudit}};
#[derive(Clone,Debug,Default,Serialize,Deserialize)]pub struct Summary{pub logical_bytes:u64,pub allocated_bytes:u64,pub files:u64,pub dirs:u64,pub errors:u64}
impl Summary{pub fn from_snapshot(s:&Snapshot)->Self{let n=&s.nodes[0];Self{logical_bytes:n.logical,allocated_bytes:n.allocated,files:n.files as u64,dirs:n.dirs as u64,errors:s.stats.errors}}}
#[derive(Clone,Debug,Serialize,Deserialize)]pub struct Target{pub id:uuid::Uuid,pub path:PathBuf,pub reason:String,pub marked_unix:u64,pub identity:Identity,pub summary:Summary,pub git:Option<GitAudit>}
#[derive(Clone,Debug,Serialize,Deserialize)]pub struct Plan{pub schema_version:u32,pub revision:uuid::Uuid,pub created_unix:u64,pub updated_unix:u64,pub targets:Vec<Target>}
impl Default for Plan{fn default()->Self{let now=platform::now_unix();Self{schema_version:1,revision:uuid::Uuid::new_v4(),created_unix:now,updated_unix:now,targets:Vec::new()}}}
pub struct Store{pub path:PathBuf,lock:File,pub plan:Plan}
impl Store{
    pub fn open(path:&Path)->Result<Self>{
        let path=platform::absolute(path)?;let parent=path.parent().context("plan needs a parent directory")?;
        std::fs::create_dir_all(parent)?;reject_reparse_ancestors(parent,true)?;
        let lock_path=path.with_extension("json.lock");
        if lock_path.exists(){ensure!(!platform::identity(&lock_path)?.is_reparse(),"plan lock must not be a reparse point");}
        let mut options=OpenOptions::new();options.read(true).write(true).create(true);
        #[cfg(windows)]{use std::os::windows::fs::OpenOptionsExt;options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);}
        let lock=options.open(&lock_path)?;
        fs2::FileExt::try_lock_exclusive(&lock).context("plan is in use by another disk-cleaner process")?;
        let plan=if path.exists(){ensure!(!platform::identity(&path)?.is_reparse(),"plan must not be a reparse point");let f=File::open(&path)?;ensure!(f.metadata()?.len()<64*1024*1024,"plan is unexpectedly large");let p:Plan=serde_json::from_reader(BufReader::new(f)).context("read plan JSON (not executable instructions)")?;ensure!(p.schema_version==1,"unsupported plan schema");ensure!(p.targets.len()<=10000,"too many targets");p}else{Plan::default()};
        Ok(Self{path,lock,plan})
    }
    pub fn save(&mut self)->Result<()>{
        self.plan.revision=uuid::Uuid::new_v4();self.plan.updated_unix=platform::now_unix();
        let tmp=self.path.with_extension(format!("{}.tmp",uuid::Uuid::new_v4()));let f=OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        {let mut w=BufWriter::new(&f);serde_json::to_writer_pretty(&mut w,&self.plan)?;w.write_all(b"\n")?;w.flush()?;}f.sync_all()?;drop(f);platform::atomic_replace(&tmp,&self.path)
    }
}
impl Drop for Store{fn drop(&mut self){let _=fs2::FileExt::unlock(&self.lock);}}

/// Reject device namespaces, ADS, globbing and relative-drive aliases up front.
pub fn literal_absolute(input:&Path)->Result<PathBuf>{
    let s=input.to_str().context("non-Unicode command paths are not supported for cleanup; no lossy conversion allowed")?;
    ensure!(!s.contains('\0'),"NUL in cleanup path");
    #[cfg(windows)]{
        let s=s.strip_prefix(r"\\?\").unwrap_or(s);ensure!(!s.starts_with(r"\\")&&!s.to_ascii_uppercase().starts_with("GLOBALROOT"),"only local drive-letter paths are accepted for cleanup");
        ensure!(!s.contains('*')&&!s.contains('?'),"cleanup targets are literal paths, never globs");
        for(i,c)in s.chars().enumerate(){ensure!(c!=':'||i==1,"alternate data streams/device names are not cleanup targets");}
        if s.as_bytes().get(1)==Some(&b':'){ensure!(s.as_bytes().get(2).is_some_and(|c|*c==b'\\'||*c==b'/'),"drive-relative paths such as C:foo are ambiguous");}
    }
    let absolute=platform::absolute(input)?;let mut normalized=PathBuf::new();for c in absolute.components(){match c{Component::CurDir=>{},Component::ParentDir=>{ensure!(normalized.pop(),"cleanup path escapes its root");},_=>normalized.push(c.as_os_str())}}
    Ok(normalized)
}
/// No traversal through junctions/symlinks/mount points. The leaf may be a link:
/// it will be unlinked as a leaf, never traversed.
pub fn reject_reparse_ancestors(path:&Path,include_leaf:bool)->Result<()>{
    let end=if include_leaf{path}else{path.parent().context("target has no parent")?};let mut chain:Vec<_>=end.ancestors().collect();chain.reverse();
    for p in chain{if p.as_os_str().is_empty(){continue;}let id=platform::identity(p).with_context(||format!("validate ancestor {}",p.display()))?;ensure!(!id.is_reparse(),"refusing to traverse reparse-point ancestor {}",p.display());}
    Ok(())
}
pub fn validate_target(input:&Path,plan_path:&Path)->Result<(PathBuf,Identity)>{
    let path=literal_absolute(input)?;reject_reparse_ancestors(&path,false)?;
    let parent=platform::canonical(path.parent().context("volume roots cannot be removed")?)?;let name=path.file_name().context("volume roots cannot be removed")?;let canonical=parent.join(name);
    let identity=platform::identity(&canonical)?;let volume=platform::volume_info(&canonical)?;
    ensure!(platform::path_key(&canonical)!=platform::path_key(&volume.root),"volume roots are protected");
    for protected in [std::env::current_dir()?,std::env::current_exe()?,platform::absolute(plan_path)?]{ensure!(!platform::within(&protected,&canonical),"target contains the current workspace, running executable, or active plan: {}",protected.display());}
    for key in ["SystemRoot","WINDIR"]{if let Some(p)=std::env::var_os(key){ensure!(!platform::within(&canonical,Path::new(&p)),"Windows system directories are protected");}}
    for key in ["USERPROFILE","ProgramFiles","ProgramFiles(x86)","ProgramData"]{if let Some(p)=std::env::var_os(key){ensure!(platform::path_key(&canonical)!=platform::path_key(Path::new(&p)),"profile/application root is protected");}}
    let display=PathBuf::from(platform::display_path(&canonical));let components:Vec<_>=display.components().filter_map(|c|if let Component::Normal(s)=c{Some(s.to_string_lossy().to_lowercase())}else{None}).collect();
    ensure!(!components.iter().any(|s|s==".git"),"direct removal inside .git is forbidden; stage the entire repository instead");
    if let Some(first)=components.first(){ensure!(!["windows","system volume information","$recycle.bin","$extend","$mft","$mftmirr","$logfile","$bitmap","$boot","$secure","pagefile.sys","hiberfil.sys","swapfile.sys","boot","recovery"].contains(&first.as_str()),"OS/volume-managed paths are protected");if components.len()==1{ensure!(!["users","program files","program files (x86)","programdata"].contains(&first.as_str()),"system container root is protected");}}
    Ok((canonical,identity))
}
pub fn stage(plan_path:&Path,paths:&[PathBuf],recursive:bool,force:bool,reason:&str,threads:usize)->Result<Vec<Target>>{
    ensure!(reason.chars().count()<=2000,"reason is limited to 2000 characters");let mut store=Store::open(plan_path)?;let mut additions=Vec::new();
    for path in paths{
        if force{match std::fs::symlink_metadata(path){Err(e)if e.kind()==std::io::ErrorKind::NotFound=>continue,Err(e)=>return Err(e).context("inspect staged target"),Ok(_)=>{}}}
        let(path,identity)=validate_target(path,&store.path)?;ensure!(!identity.is_dir()||identity.is_reparse()||recursive,"directory requires -r/--recursive (still stage-only)");
        for existing in store.plan.targets.iter().chain(additions.iter()){ensure!(!platform::within(&path,&existing.path)&&!platform::within(&existing.path,&path),"overlapping target already staged: {}; undo-rm it first",existing.path.display());}
        let summary=if identity.is_dir()&&!identity.is_reparse(){Summary::from_snapshot(&scan::fs::scan(&path,platform::volume_info(&path)?,threads,512*1024*1024)?)}else{Summary{logical_bytes:identity.length,allocated_bytes:identity.allocated,files:1,..Default::default()}};
        let git=git_audit::inspect(&path,false).unwrap_or_else(|e|Some(GitAudit{root:path.clone(),risks:vec![format!("Git check failed: {e:#}")],..Default::default()}));
        additions.push(Target{id:uuid::Uuid::new_v4(),path,reason:reason.into(),marked_unix:platform::now_unix(),identity,summary,git});
    }
    store.plan.targets.extend(additions.clone());if !additions.is_empty(){store.save()?;}Ok(additions)
}
pub fn undo(plan_path:&Path,paths:&[PathBuf],all:bool)->Result<usize>{let mut store=Store::open(plan_path)?;let keys=paths.iter().map(|p|literal_absolute(p).map(|p|platform::path_key(&p))).collect::<Result<Vec<_>>>()?;let before=store.plan.targets.len();store.plan.targets.retain(|t|!all&&!keys.contains(&platform::path_key(&t.path)));let removed=before-store.plan.targets.len();if removed>0{store.save()?;}Ok(removed)}

#[cfg(test)]mod tests{use super::*;
    #[test]fn rm_and_undo_never_delete(){let d=tempfile::tempdir().unwrap();let file=d.path().join("precious.txt");let p=d.path().join("plan.json");std::fs::write(&file,b"keep me").unwrap();stage(&p,&[file.clone()],false,false,"test",2).unwrap();assert_eq!(std::fs::read(&file).unwrap(),b"keep me");assert_eq!(Store::open(&p).unwrap().plan.targets.len(),1);undo(&p,&[file.clone()],false).unwrap();assert!(file.exists());assert!(Store::open(&p).unwrap().plan.targets.is_empty());}
    #[test]fn rejects_volume_and_current_dir(){let p=std::env::temp_dir().join("plan.json");assert!(validate_target(&std::env::current_dir().unwrap(),&p).is_err());#[cfg(windows)]assert!(validate_target(Path::new("C:/"),&p).is_err());}
    #[test]fn overlapping_marks_rejected(){let d=tempfile::tempdir().unwrap();let dir=d.path().join("data");std::fs::create_dir(&dir).unwrap();let file=dir.join("x");std::fs::write(&file,b"x").unwrap();let p=d.path().join("plan.json");stage(&p,&[file.clone()],false,false,"",1).unwrap();assert!(stage(&p,&[dir],true,false,"",1).is_err());assert!(file.exists());}
    #[test]fn refuses_globs_and_ads(){#[cfg(windows)]{assert!(literal_absolute(Path::new("C:/data/*")).is_err());assert!(literal_absolute(Path::new("C:/data/file:stream")).is_err());assert!(literal_absolute(Path::new("C:file")).is_err());}}
}
