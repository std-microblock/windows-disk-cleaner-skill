//! GUI-only execution. No public/headless command can mint an Approval.
//! Deletes the reviewed manifest by verified handles, never remove_dir_all.
use anyhow::{Result,Context,ensure,bail};
use std::{collections::{BTreeMap,BTreeSet},fs::{File,OpenOptions},io::Write,path::{Path,PathBuf},sync::{Arc,atomic::{AtomicBool,Ordering},mpsc::{self,Sender,SyncSender}}};
use serde::Serialize;
use crate::{platform::{self,Identity,VolumeInfo},plan::{self,Plan,Target,Store},model::Snapshot,scan,git_audit::{self,GitAudit},locks,selection::TreeSelection};
#[derive(Debug)]pub struct PreparedTarget{pub target:Target,pub tree:Snapshot,pub identities:Vec<Identity>,pub digest:[u8;32]}
#[derive(Debug)]pub struct Prepared{pub plan_path:PathBuf,pub plan:Plan,pub targets:Vec<PreparedTarget>,pub git:Vec<GitAudit>,pub problems:Vec<String>,pub volumes:Vec<VolumeInfo>,pub total_items:u64,pub allocated_upper_bound:u64}
impl Prepared{pub fn git_risk(&self)->bool{self.git.iter().any(GitAudit::needs_confirmation)}pub fn can_delete(&self)->bool{self.problems.is_empty()&&!self.targets.is_empty()}}
#[derive(Clone,Copy,Debug)]pub enum LockDecision{Skip,Retry,CloseGracefully,ForceClose}
#[derive(Clone,Debug,Default,Serialize)]pub struct Outcome{pub processed:u64,pub removed:u64,pub failed:u64,pub removed_bytes:u64,pub cancelled:bool,pub errors:Vec<String>,pub before:Vec<VolumeInfo>,pub after:Vec<VolumeInfo>}
pub enum Event{Preparing(String),Ready(Arc<Prepared>),Fatal(String),Progress{done:u64,total:u64,removed:u64,failed:u64,current:String},Locked{path:String,owners:Vec<locks::Owner>,detail:String,response:SyncSender<LockDecision>},Finished(Outcome)}
/// Deliberately not Deserialize, not constructible from CLI arguments or plan JSON.
pub(crate) struct Approval{revision:uuid::Uuid,git_acknowledged:bool,selection:Vec<TreeSelection>}
impl Approval{pub(crate) fn from_gui(prepared:&Prepared,selection:&[TreeSelection],git_acknowledged:bool)->Result<Self>{
    ensure!(prepared.can_delete(),"review has unresolved problems");ensure!(selection.len()==prepared.targets.len()&&selection.iter().zip(&prepared.targets).all(|(s,t)|s.len()==t.tree.nodes.len()),"selection does not match the reviewed trees");
    ensure!(selection.iter().any(|s|s.totals(0).items()>0),"no files or folders are checked");
    ensure!(!selected_git_risk(prepared,selection)||git_acknowledged,"unsynced/unknown Git data needs a separate confirmation");
    for(t,s)in prepared.targets.iter().zip(selection){for id in s.selected_roots(&t.tree){plan::validate_target(&t.tree.path(id),&prepared.plan_path)?;}}
    Ok(Self{revision:prepared.plan.revision,git_acknowledged,selection:selection.to_vec()})
}}
pub fn selected_git<'a>(prepared:&'a Prepared,selection:&[TreeSelection])->Vec<&'a GitAudit>{
    let paths:Vec<_>=prepared.targets.iter().zip(selection).flat_map(|(t,s)|s.selected_roots(&t.tree).into_iter().map(|id|t.tree.path(id))).collect();
    prepared.git.iter().filter(|g|paths.iter().any(|p|platform::within(p,&g.root)||platform::within(&g.root,p))).collect()
}
pub fn selected_git_risk(prepared:&Prepared,selection:&[TreeSelection])->bool{selected_git(prepared,selection).iter().any(|g|g.needs_confirmation())}
fn emit(sender:&Sender<Event>,event:Event){let _=sender.send(event);}
fn manifest_digest(tree:&Snapshot,identities:&[Identity])->Result<[u8;32]>{
    ensure!(tree.nodes.len()==identities.len(),"manifest identity count mismatch");
    let mut digest=blake3::Hasher::new();let mut stack=vec![0u32];
    while let Some(id)=stack.pop(){let n=&tree.nodes[id as usize];let m=identities[id as usize];let name=tree.name_units(id);digest.update(&(name.len() as u64).to_le_bytes());for c in name{digest.update(&c.to_le_bytes());}digest.update(&m.volume.to_le_bytes());digest.update(&m.id);digest.update(&m.length.to_le_bytes());digest.update(&m.modified.to_le_bytes());digest.update(&m.attributes.to_le_bytes());
        let mut children:Vec<_>=tree.children(id).collect();children.sort_by(|&a,&b|tree.name_units(b).cmp(tree.name_units(a)));digest.update(&(children.len() as u64).to_le_bytes());stack.extend(children);let _=n;
    }Ok(*digest.finalize().as_bytes())
}
fn capture(target:&Target,threads:usize)->Result<PreparedTarget>{
    let(tree,identities)=scan::fs::capture(&target.path,platform::volume_info(&target.path)?,threads,768*1024*1024,true)?;
    ensure!(tree.stats.complete,"cannot prepare an incomplete subtree: {} read errors; {}",tree.stats.errors,tree.stats.warnings.join("; "));
    ensure!(identities[0].same_file(&target.identity),"target was replaced since it was staged");
    let digest=manifest_digest(&tree,&identities)?;Ok(PreparedTarget{target:target.clone(),tree,identities,digest})
}
pub fn prepare(plan_path:&Path,fetch:bool,threads:usize,sender:&Sender<Event>)->Result<Prepared>{
    let store=Store::open(plan_path)?;let plan=store.plan.clone();let plan_path=store.path.clone();drop(store);
    let mut p=Prepared{plan_path,plan,targets:Vec::new(),git:Vec::new(),problems:Vec::new(),volumes:Vec::new(),total_items:0,allocated_upper_bound:0};
    let mut repos=BTreeSet::new();let mut volumes=BTreeMap::new();
    for target in &p.plan.targets{
        emit(sender,Event::Preparing(format!("Reading reviewed manifest: {}",platform::display_path(&target.path))));
        let result=(||->Result<PreparedTarget>{let(path,identity)=plan::validate_target(&target.path,&p.plan_path)?;ensure!(identity.same_file(&target.identity),"staged path now points to a different file");ensure!(platform::path_key(&path)==platform::path_key(&target.path),"staged canonical path changed");
            for other in &p.plan.targets{if other.id!=target.id{ensure!(!platform::within(&target.path,&other.path)&&!platform::within(&other.path,&target.path),"plan was edited to contain overlapping targets");}}
            capture(target,threads)
        })();
        match result{
            Ok(prepared)=>{
                volumes.entry(platform::path_key(&prepared.tree.volume.root)).or_insert_with(||prepared.tree.volume.clone());
                repos.insert(target.path.clone());
                for i in 1..prepared.tree.nodes.len(){if prepared.tree.name(i as u32)==".git"{let parent=prepared.tree.nodes[i].parent;repos.insert(prepared.tree.path(parent));}}
                p.targets.push(prepared);
            },Err(e)=>p.problems.push(format!("{}: {e:#}",target.path.display())),
        }
    }
    let mut checked=BTreeSet::new();
    for candidate in repos{
        emit(sender,Event::Preparing(format!("Checking Git{}: {}",if fetch{" + remotes"}else{" (local evidence)"},platform::display_path(&candidate))));
        match git_audit::inspect(&candidate,fetch){Ok(Some(audit))=>{if checked.insert(platform::path_key(&audit.root)){p.git.push(audit);}},Ok(None)=>{},Err(e)=>p.git.push(GitAudit{root:candidate,risks:vec![format!("Git safety unknown: {e:#}")],..Default::default()})}
    }
    // fetch writes Git objects/remote tracking refs. The manifest must be captured AFTER it.
    if fetch{for item in &mut p.targets{match capture(&item.target,threads){Ok(fresh)=>*item=fresh,Err(e)=>p.problems.push(format!("post-fetch snapshot: {e:#}"))}}}
    for t in &p.targets{p.total_items+=t.tree.nodes.len() as u64;p.allocated_upper_bound+=t.tree.nodes[0].allocated;}
    p.volumes=volumes.into_values().collect();Ok(p)
}
#[cfg(windows)]fn open_delete_handle(path:&Path,delete_this:bool)->Result<File>{
    use std::os::windows::fs::OpenOptionsExt;use windows_sys::Win32::Storage::FileSystem::*;
    // No SHARE_WRITE/SHARE_DELETE: the checked object cannot be replaced or written
    // while we inspect and mark its exact handle for deletion. Occupants get a dialog.
    OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES|if delete_this{DELETE}else{0}).share_mode(FILE_SHARE_READ).custom_flags(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT).open(path).with_context(||format!("open deletion handle: {}",path.display()))
}
#[cfg(windows)]fn unlink_handle(file:&File)->Result<()>{
    use std::os::windows::io::AsRawHandle;use windows_sys::Win32::Storage::FileSystem::*;
    let info=FILE_DISPOSITION_INFO_EX{Flags:FILE_DISPOSITION_FLAG_DELETE|FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE};
    let ok=unsafe{SetFileInformationByHandle(file.as_raw_handle(),FileDispositionInfoEx,(&info as *const FILE_DISPOSITION_INFO_EX).cast(),std::mem::size_of_val(&info) as u32)};
    if ok==0{return Err(std::io::Error::last_os_error()).context("delete verified handle");}Ok(())
}
#[cfg(not(windows))]fn open_delete_handle(_:&Path,_:bool)->Result<File>{bail!("safe deletion requires Windows handle semantics")}
#[cfg(not(windows))]fn unlink_handle(_:&File)->Result<()>{bail!("safe deletion requires Windows handle semantics")}

struct Executor<'a>{sender:&'a Sender<Event>,cancel:&'a AtomicBool,outcome:Outcome,total:u64,audit:File,last_progress:std::time::Instant}
impl Executor<'_>{
    fn progress(&mut self,path:&Path){if self.outcome.processed<self.total&&self.last_progress.elapsed()<std::time::Duration::from_millis(50){return;}self.last_progress=std::time::Instant::now();emit(self.sender,Event::Progress{done:self.outcome.processed,total:self.total,removed:self.outcome.removed,failed:self.outcome.failed,current:platform::display_path(path)});}
    fn error(&mut self,path:&Path,e:impl std::fmt::Display){self.outcome.failed+=1;if self.outcome.errors.len()<100{self.outcome.errors.push(format!("{}: {e}",platform::display_path(path)));}}
    fn lock_decision(&mut self,path:&Path,error:&anyhow::Error)->Result<bool>{
        let session=locks::Session::for_file(path).ok();let owners=session.as_ref().and_then(|s|s.owners().ok()).unwrap_or_default();let(tx,rx)=mpsc::sync_channel(1);
        self.sender.send(Event::Locked{path:platform::display_path(path),owners:owners.clone(),detail:format!("{error:#}"),response:tx}).context("review window closed")?;
        loop{if self.cancel.load(Ordering::Relaxed){return Ok(false);}match rx.recv_timeout(std::time::Duration::from_millis(100)){
            Ok(LockDecision::Skip)=>return Ok(false),Ok(LockDecision::Retry)=>return Ok(true),
            Ok(LockDecision::CloseGracefully)=>{session.context("owner could not be identified")?.shutdown(&owners,false)?;return Ok(true);},
            Ok(LockDecision::ForceClose)=>{session.context("owner could not be identified")?.shutdown(&owners,true)?;return Ok(true);},
            Err(mpsc::RecvTimeoutError::Timeout)=>{},Err(_)=>return Ok(false),
        }}
    }
    fn open_reviewed(&mut self,path:&Path,expected:Identity,delete_this:bool)->Result<Option<File>>{
        for _ in 0..3{match open_delete_handle(path,delete_this){
            Ok(file)=>{let actual=platform::identity_from_handle(&file)?;ensure!(actual.same_file(&expected)&&actual.attributes&0x410==expected.attributes&0x410,"target identity/type changed since review");if !actual.is_dir(){ensure!(actual.length==expected.length&&actual.modified==expected.modified,"file changed after review; refresh required");}return Ok(Some(file));},
            Err(e)if locks::may_be_locked(&e)=>{if !self.lock_decision(path,&e)?{return Ok(None);}},
            Err(e)=>return Err(e),
        }}bail!("still occupied after three user-directed attempts")
    }
    fn delete_node(&mut self,target:&PreparedTarget,selection:&TreeSelection,id:u32,depth:usize)->bool{
        if selection.totals(id).items()==0{return true;}
        if self.cancel.load(Ordering::Relaxed){return false;}let path=target.tree.path(id);if depth>256{self.error(&path,"directory nesting exceeds safe deletion depth");return false;}
        let expected=target.identities[id as usize];
        let file=match self.open_reviewed(&path,expected,selection.selected(id)){Ok(Some(file))=>file,Ok(None)=>{self.outcome.processed+=1;self.error(&path,"skipped occupied item");self.progress(&path);return false;},Err(e)=>{self.outcome.processed+=1;self.error(&path,format!("{e:#}"));self.progress(&path);return false;}};
        // The opened parent directory stays pinned until all its reviewed children
        // are processed. New children are NEVER enumerated/deleted during execution.
        let mut children_ok=true;
        if expected.is_dir()&&!expected.is_reparse(){for child in target.tree.children(id){if !self.delete_node(target,selection,child,depth+1){children_ok=false;}if self.cancel.load(Ordering::Relaxed){return false;}}}
        if !selection.selected(id){return children_ok;}
        if !children_ok{self.outcome.processed+=1;self.error(&path,"kept directory because a reviewed child was not removed");self.progress(&path);return false;}
        let success=match unlink_handle(&file){Ok(())=>true,Err(e)=>{self.error(&path,format!("{e:#}"));false}};
        drop(file);self.outcome.processed+=1;if success{self.outcome.removed+=1;if !expected.is_dir(){self.outcome.removed_bytes=self.outcome.removed_bytes.saturating_add(expected.allocated);}}self.progress(&path);success
    }
}

pub(crate) fn execute(prepared:Arc<Prepared>,approval:Approval,cancel:Arc<AtomicBool>,sender:Sender<Event>,threads:usize)->Result<Outcome>{
    ensure!(approval.revision==prepared.plan.revision&&(!selected_git_risk(&prepared,&approval.selection)||approval.git_acknowledged),"approval does not match reviewed plan/Git risk");
    ensure!(prepared.can_delete(),"review is incomplete");let mut store=Store::open(&prepared.plan_path)?;ensure!(store.plan.revision==approval.revision,"plan changed while window was open; refresh and confirm again");
    // Re-enumerate every reviewed target BEFORE deleting anything. A late-created
    // file, changed inode, changed content metadata or new Git file cancels the run.
    for (target,selection) in prepared.targets.iter().zip(&approval.selection){
        if selection.totals(0).items()==0{continue;}
        if cancel.load(Ordering::Relaxed){return Ok(Outcome{cancelled:true,..Default::default()});}
        emit(&sender,Event::Preparing(format!("Revalidating before deletion: {}",platform::display_path(&target.target.path))));
        let(_,identity)=plan::validate_target(&target.target.path,&prepared.plan_path)?;ensure!(identity.same_file(&target.target.identity),"staged target replaced");let fresh=capture(&target.target,threads)?;ensure!(fresh.digest==target.digest,"{} changed after review; NOTHING has been deleted; refresh and reconfirm",target.target.path.display());
    }
    let audit_path=prepared.plan_path.with_extension("audit.jsonl");if audit_path.exists(){ensure!(!platform::identity(&audit_path)?.is_reparse(),"audit log may not be a reparse point");}
    let audit=OpenOptions::new().create(true).append(true).open(&audit_path)?;
    let before:Vec<_>=prepared.volumes.iter().filter_map(|v|platform::volume_info(&v.root).ok()).collect();
    let mut executor=Executor{sender:&sender,cancel:&cancel,outcome:Outcome{before,..Default::default()},total:approval.selection.iter().map(|s|s.totals(0).items()).sum(),audit,last_progress:std::time::Instant::now()};
    serde_json::to_writer(&mut executor.audit,&serde_json::json!({"event":"gui-confirmed-start","time":platform::now_unix(),"revision":prepared.plan.revision,"git_risk_acknowledged":approval.git_acknowledged,"targets":prepared.targets.iter().zip(&approval.selection).flat_map(|(t,s)|s.selected_roots(&t.tree).into_iter().map(move|id|serde_json::json!({"path":t.tree.path(id),"reason":t.target.reason}))).collect::<Vec<_>>()}))?;executor.audit.write_all(b"\n")?;executor.audit.sync_all()?;
    let mut completed=Vec::new();
    for (target,selection) in prepared.targets.iter().zip(&approval.selection){if selection.totals(0).items()==0{continue;}if cancel.load(Ordering::Relaxed){break;}
        // Pin all pre-existing ancestors too. They cannot be exchanged for junctions
        // between validation and the handle-relative reviewed walk.
        let mut guards=Vec::new();let parent=target.target.path.parent().context("target has no parent")?;let mut chain:Vec<_>=parent.ancestors().collect();chain.reverse();
        let guard_result=(||->Result<()>{for ancestor in chain{if ancestor.as_os_str().is_empty(){continue;}let h=open_delete_handle(ancestor,false)?;ensure!(!platform::identity_from_handle(&h)?.is_reparse(),"ancestor became a reparse point");guards.push(h);}Ok(())})();
        if let Err(e)=guard_result{executor.error(&target.target.path,format!("ancestor guard: {e:#}"));continue;}
        if executor.delete_node(target,selection,0,0){completed.push(target.target.id);}
        else if selection.state(&target.tree,0)!=2{
            // A partially executed target must not later expand back to the whole
            // directory. Replace its mark with remaining selected subtrees only.
            completed.push(target.target.id);
        }
        drop(guards);
    }
    executor.outcome.cancelled=cancel.load(Ordering::Relaxed);executor.outcome.after=prepared.volumes.iter().filter_map(|v|platform::volume_info(&v.root).ok()).collect();
    let mut remaining=Vec::new();
    for(t,s)in prepared.targets.iter().zip(&approval.selection){
        if s.state(&t.tree,0)==2{continue;}
        if s.totals(0).items()==0{continue;}
        // Preserve only explicitly selected, still-existing roots on partial runs.
        for id in s.selected_roots(&t.tree){let path=t.tree.path(id);if let Ok(identity)=platform::identity(&path){remaining.push(Target{id:uuid::Uuid::new_v4(),path,reason:t.target.reason.clone(),marked_unix:platform::now_unix(),identity,summary:crate::plan::Summary{logical_bytes:t.tree.nodes[id as usize].logical,allocated_bytes:t.tree.nodes[id as usize].allocated,files:t.tree.nodes[id as usize].files as u64,dirs:t.tree.nodes[id as usize].dirs as u64,errors:0},git:t.target.git.clone()});}}
        if !completed.contains(&t.target.id){completed.push(t.target.id);}
    }
    store.plan.targets.retain(|t|!completed.contains(&t.id));store.plan.targets.extend(remaining);if !completed.is_empty(){store.save()?;}
    serde_json::to_writer(&mut executor.audit,&serde_json::json!({"event":"finished","time":platform::now_unix(),"outcome":executor.outcome}))?;executor.audit.write_all(b"\n")?;executor.audit.sync_all()?;
    Ok(executor.outcome)
}
#[cfg(test)]mod tests{use super::*;
    #[test]fn manifest_change_is_detected(){let d=tempfile::tempdir().unwrap();let data=d.path().join("data");std::fs::create_dir(&data).unwrap();let f=data.join("a");std::fs::write(&f,b"original").unwrap();let plan=d.path().join("plan.json");plan::stage(&plan,&[data.clone()],true,false,"test fixture",1).unwrap();let(tx,_)=mpsc::channel();let prepared=prepare(&plan,false,1,&tx).unwrap();let old=prepared.targets[0].digest;std::fs::write(&f,b"new content").unwrap();let fresh=capture(&prepared.targets[0].target,1).unwrap();assert_ne!(old,fresh.digest);assert!(f.exists());}
    #[test]fn approval_rejects_unknown_git(){let p=Prepared{plan_path:PathBuf::new(),plan:Plan::default(),targets:Vec::new(),git:vec![GitAudit::default()],problems:Vec::new(),volumes:Vec::new(),total_items:0,allocated_upper_bound:0};assert!(Approval::from_gui(&p,&[],false).is_err());}

    fn staged_fixture()->(tempfile::TempDir,PathBuf,PathBuf,Arc<Prepared>){
        let d=tempfile::tempdir().unwrap();let data=d.path().join("reviewed");std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("remove.txt"),b"fixture only").unwrap();std::fs::write(data.join("keep.txt"),b"canary").unwrap();
        let plan_path=d.path().join("plan.json");plan::stage(&plan_path,&[data.clone()],true,false,"isolated test fixture",2).unwrap();
        let(tx,_)=mpsc::channel();let p=Arc::new(prepare(&plan_path,false,2,&tx).unwrap());(d,plan_path,data,p)
    }
    #[test]fn executes_only_checked_files_and_keeps_partial_parent(){
        let(_d,plan_path,data,p)=staged_fixture();let tree=&p.targets[0].tree;let mut s=TreeSelection::all(tree);
        let keep=tree.find(&data.join("keep.txt")).unwrap();s.set_subtree(tree,keep,false);let approval=Approval::from_gui(&p,&[s],false).unwrap();
        let(tx,_rx)=mpsc::channel();let outcome=execute(p,approval,Arc::new(AtomicBool::new(false)),tx,2).unwrap();
        assert_eq!(outcome.removed,1,"{outcome:?}");assert!(data.is_dir());assert_eq!(std::fs::read(data.join("keep.txt")).unwrap(),b"canary");assert!(!data.join("remove.txt").exists());assert!(Store::open(&plan_path).unwrap().plan.targets.is_empty());
    }
    #[test]fn full_selection_removes_fixture_tree_only(){
        let(d,plan_path,data,p)=staged_fixture();let outside=d.path().join("outside.txt");std::fs::write(&outside,b"outside").unwrap();
        let selection=vec![TreeSelection::all(&p.targets[0].tree)];let approval=Approval::from_gui(&p,&selection,false).unwrap();let(tx,_rx)=mpsc::channel();
        let o=execute(p,approval,Arc::new(AtomicBool::new(false)),tx,2).unwrap();assert_eq!(o.failed,0,"{o:?}");assert_eq!(o.removed,3);assert!(!data.exists());assert!(outside.exists());assert!(Store::open(&plan_path).unwrap().plan.targets.is_empty());
    }
    #[test]fn changed_after_approval_aborts_before_any_deletion(){
        let(_d,_plan,data,p)=staged_fixture();let approval=Approval::from_gui(&p,&[TreeSelection::all(&p.targets[0].tree)],false).unwrap();std::fs::write(data.join("late-file.txt"),b"not reviewed").unwrap();
        let(tx,_)=mpsc::channel();assert!(execute(p,approval,Arc::new(AtomicBool::new(false)),tx,2).is_err());assert!(data.join("remove.txt").exists());assert!(data.join("late-file.txt").exists());
    }
    #[test]fn cancelled_before_start_preserves_all_files(){
        let(_d,_plan,data,p)=staged_fixture();let approval=Approval::from_gui(&p,&[TreeSelection::all(&p.targets[0].tree)],false).unwrap();let(tx,_)=mpsc::channel();
        let o=execute(p,approval,Arc::new(AtomicBool::new(true)),tx,2).unwrap();assert!(o.cancelled);assert!(data.join("remove.txt").exists());assert!(data.join("keep.txt").exists());
    }
    #[cfg(windows)]
    #[test]fn occupied_file_requires_a_decision_and_skip_preserves_it(){
        use std::os::windows::fs::OpenOptionsExt;
        let(_d,_plan,data,p)=staged_fixture();let _held=OpenOptions::new().read(true).share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ).open(data.join("keep.txt")).unwrap();
        let approval=Approval::from_gui(&p,&[TreeSelection::all(&p.targets[0].tree)],false).unwrap();let(tx,rx)=mpsc::channel();
        let worker=std::thread::spawn(move||{let mut prompts=0;while let Ok(event)=rx.recv(){if let Event::Locked{response,..}=event{prompts+=1;response.send(LockDecision::Skip).unwrap();}}prompts});
        let o=execute(p,approval,Arc::new(AtomicBool::new(false)),tx,2).unwrap();assert_eq!(worker.join().unwrap(),1);assert!(o.failed>0);assert!(data.join("keep.txt").exists());assert!(data.exists());
    }
}
