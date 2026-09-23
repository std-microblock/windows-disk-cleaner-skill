//! Conservative Git evidence. Cached refs are never described as remote proof.
use anyhow::{Context,Result};
use git2::{AutotagOption,BranchType,Cred,FetchOptions,Oid,RemoteCallbacks,Repository,RepositoryState,Status,StatusOptions};
use serde::{Serialize,Deserialize};
use std::{collections::BTreeSet,path::{Path,PathBuf},sync::Once};
use crate::platform;
#[derive(Clone,Debug,Default,Serialize,Deserialize)]
pub struct GitAudit{
    pub root:PathBuf,pub git_dir:PathBuf,pub branch:Option<String>,pub bare:bool,pub detached:bool,
    pub modified:u64,pub staged:u64,pub untracked:u64,pub ignored:u64,pub conflicts:u64,pub stashes:u64,
    pub remote_verified:bool,pub tracked_history_covered:bool,pub all_content_synced:bool,
    pub remotes:Vec<String>,pub local_only_refs:Vec<String>,pub risks:Vec<String>,pub checked_unix:u64,
}
impl GitAudit{
    pub fn needs_confirmation(&self)->bool{!self.all_content_synced||!self.risks.is_empty()}
    pub fn concise(&self)->String{
        format!("git:{} branch={} changed={} staged={} untracked={} ignored={} stash={} local-refs={} remote={}",if self.all_content_synced{"covered"}else{"LOCAL-DATA"},self.branch.as_deref().unwrap_or(if self.detached{"detached"}else{"unborn"}),self.modified,self.staged,self.untracked,self.ignored,self.stashes,self.local_only_refs.len(),if self.remote_verified{"verified"}else{"UNVERIFIED"})
    }
}
fn configure_timeouts(){static ONCE:Once=Once::new();ONCE.call_once(||unsafe{let _=git2::opts::set_server_connect_timeout_in_milliseconds(5000);let _=git2::opts::set_server_timeout_in_milliseconds(10000);});}
fn callbacks()->RemoteCallbacks<'static>{
    let mut callbacks=RemoteCallbacks::new();
    callbacks.credentials(|url,username,allowed|{
        if allowed.contains(git2::CredentialType::SSH_KEY){return Cred::ssh_key_from_agent(username.unwrap_or("git"));}
        if allowed.contains(git2::CredentialType::USER_PASS_PLAINTEXT){if let Ok(config)=git2::Config::open_default(){if let Ok(c)=Cred::credential_helper(&config,url,username){return Ok(c);}}}
        if allowed.contains(git2::CredentialType::USERNAME){return Cred::username(username.unwrap_or("git"));}
        Cred::default()
    });callbacks
}
/// fetch=true is an explicit read-network operation. It updates only remote-tracking
/// branches, never worktree files, local branches, or local tags. No hooks are run.
pub fn inspect(path:&Path,fetch:bool)->Result<Option<GitAudit>>{
    configure_timeouts();let search=if path.is_file(){path.parent().unwrap_or(path)}else{path};
    let mut repo=match Repository::discover(search){Ok(r)=>r,Err(e)if e.code()==git2::ErrorCode::NotFound=>return Ok(None),Err(e)=>return Err(e).context("discover Git repository")};
    let root=repo.workdir().unwrap_or_else(||repo.path()).to_path_buf();
    let mut audit=GitAudit{root:root.clone(),git_dir:repo.path().to_path_buf(),bare:repo.is_bare(),checked_unix:platform::now_unix(),..Default::default()};
    audit.detached=repo.head_detached().unwrap_or(false);
    if let Ok(head)=repo.head(){audit.branch=head.shorthand().ok().map(str::to_owned);}else{audit.risks.push("unborn or unreadable HEAD".into());}
    if repo.state()!=RepositoryState::Clean{audit.risks.push(format!("repository operation in progress: {:?}",repo.state()));}
    if !audit.bare{
        let mut options=StatusOptions::new();options.include_untracked(true).include_ignored(true).recurse_untracked_dirs(false).recurse_ignored_dirs(false).exclude_submodules(false);
        match repo.statuses(Some(&mut options)){
            Ok(statuses)=>for entry in statuses.iter(){let s=entry.status();if s==Status::IGNORED{audit.ignored+=1;continue;}if s.contains(Status::WT_NEW){audit.untracked+=1;}if s.intersects(Status::WT_MODIFIED|Status::WT_DELETED|Status::WT_RENAMED|Status::WT_TYPECHANGE|Status::WT_UNREADABLE){audit.modified+=1;}if s.intersects(Status::INDEX_NEW|Status::INDEX_MODIFIED|Status::INDEX_DELETED|Status::INDEX_RENAMED|Status::INDEX_TYPECHANGE){audit.staged+=1;}if s.is_conflicted(){audit.conflicts+=1;}},
            Err(e)=>audit.risks.push(format!("worktree status unknown: {e}")),
        }
    }
    if let Err(e)=repo.stash_foreach(|_,_,_|{audit.stashes+=1;true}){audit.risks.push(format!("stash status unknown: {e}"));}
    if let Ok(worktrees)=repo.worktrees(){if !worktrees.is_empty(){audit.risks.push(format!("{} linked worktree(s); their private state is not covered by this report",worktrees.len()));}}
    if let Ok(submodules)=repo.submodules(){if !submodules.is_empty(){audit.risks.push(format!("{} submodule(s): inspect nested repositories separately",submodules.len()));}}
    // A .git file may refer to metadata outside the candidate; do not claim a self-contained backup.
    if !audit.bare&&!platform::within(&audit.git_dir,&audit.root){audit.risks.push("Git metadata is outside this worktree (linked worktree/submodule)".into());}
    let mut tips=BTreeSet::new();let mut advertised_tags=BTreeSet::new();let names=repo.remotes()?;
    audit.remotes=names.iter().collect::<std::result::Result<Vec<_>,_>>()?.into_iter().flatten().map(str::to_owned).collect();
    let mut all_remotes_ok=!audit.remotes.is_empty();
    if fetch{
        for name in &audit.remotes{
            let result=(||->Result<()>{let mut remote=repo.find_remote(name)?;
                let mut options=FetchOptions::new();options.remote_callbacks(callbacks()).download_tags(AutotagOption::None).update_fetchhead(false);
                let refspec=format!("+refs/heads/*:refs/remotes/{name}/*");
                remote.fetch(&[refspec],Some(&mut options),Some("disk-cleaner: verify remote coverage"))?;
                for head in remote.list()?{let n=head.name();if n.starts_with("refs/heads/"){tips.insert(head.oid());}else if n.starts_with("refs/tags/")&&!n.ends_with("^{}"){advertised_tags.insert(head.oid());}}
                Ok(())
            })();if let Err(e)=result{all_remotes_ok=false;audit.risks.push(format!("remote {name} unavailable/unverified: {e:#}"));}
        }
        audit.remote_verified=all_remotes_ok;
    }else{
        for reference in repo.references_glob("refs/remotes/*")?{if let Ok(reference)=reference{if let Ok(c)=reference.peel_to_commit(){tips.insert(c.id());}}}
        audit.risks.push("remote refs are CACHED, not proof of current remote contents; run git --fetch to verify".into());
    }
    if audit.remotes.is_empty(){audit.risks.push("no remote configured".into());}
    let covered=|local:Oid|->bool{tips.iter().any(|&tip|tip==local||repo.graph_descendant_of(tip,local).unwrap_or(false))};
    for branch in repo.branches(Some(BranchType::Local))?{let(branch,_)=branch?;let name=branch.name()?.unwrap_or("<non-UTF8 branch>").to_owned();match branch.get().peel_to_commit(){Ok(commit)if covered(commit.id())=>{},_=>audit.local_only_refs.push(format!("branch:{name}"))}}
    if audit.detached{match repo.head().and_then(|r|r.peel_to_commit()){Ok(commit)if covered(commit.id())=>{},_=>audit.local_only_refs.push("detached HEAD".into())}}
    for tag in repo.references_glob("refs/tags/*")?{let tag=tag?;let oid=tag.target();if !fetch||oid.is_none_or(|id|!advertised_tags.contains(&id)){audit.local_only_refs.push(tag.name().unwrap_or("<non-UTF8 tag>").to_owned());}}
    audit.tracked_history_covered=audit.remote_verified&&audit.local_only_refs.is_empty()&&repo.head().is_ok();
    if audit.modified+audit.staged+audit.conflicts>0{audit.risks.push("tracked changes/conflicts exist only locally".into());}
    if audit.untracked>0{audit.risks.push("untracked worktree entries are not in Git".into());}
    if audit.ignored>0{audit.risks.push("ignored entries are LOCAL-ONLY too; ignore does not mean disposable".into());}
    if audit.stashes>0{audit.risks.push("local stashes are not protected by ordinary push".into());}
    if !audit.local_only_refs.is_empty(){audit.risks.push("local refs/commits/tags are not proven covered by advertised remotes".into());}
    audit.all_content_synced=audit.tracked_history_covered&&audit.modified==0&&audit.staged==0&&audit.untracked==0&&audit.ignored==0&&audit.conflicts==0&&audit.stashes==0&&audit.risks.is_empty();
    Ok(Some(audit))
}
/// Classifies a visible file/folder without interpreting gitignore as deletion permission.
pub fn path_state(path:&Path)->Result<Option<(PathBuf,String)>>{
    let p=if path.is_file(){path.parent().unwrap_or(path)}else{path};let repo=match Repository::discover(p){Ok(r)=>r,Err(e)if e.code()==git2::ErrorCode::NotFound=>return Ok(None),Err(e)=>return Err(e.into())};
    let Some(root)=repo.workdir()else{return Ok(Some((repo.path().into(),"bare-repo".into())))};
    if platform::path_key(root)==platform::path_key(path){return Ok(Some((root.into(),"repo".into())));}
    let relative=path.strip_prefix(root).or_else(|_|path.strip_prefix(platform::display_path(root))).unwrap_or(path);
    let state=if repo.status_should_ignore(relative).unwrap_or(false){"ignored/local-only"}else if path.is_dir(){"worktree-dir"}else{match repo.status_file(relative){Ok(s)if s.is_empty()=>"tracked",Ok(s)if s.is_wt_new()=>"untracked",Ok(_)=>"modified",Err(_)=>"unknown"}};
    Ok(Some((root.into(),state.into())))
}

#[cfg(test)]mod tests{
    use super::*;
    fn fixture()->(tempfile::TempDir,PathBuf){let d=tempfile::tempdir().unwrap();let work=d.path().join("work");let remote=d.path().join("remote.git");Repository::init_bare(&remote).unwrap();let repo=Repository::init(&work).unwrap();std::fs::write(work.join("file.txt"),"important\n").unwrap();let mut index=repo.index().unwrap();index.add_path(Path::new("file.txt")).unwrap();index.write().unwrap();let tree_id=index.write_tree().unwrap();let tree=repo.find_tree(tree_id).unwrap();let sig=git2::Signature::now("Test","test@example.invalid").unwrap();repo.commit(Some("HEAD"),&sig,&sig,"initial",&tree,&[]).unwrap();repo.remote("origin",remote.to_str().unwrap()).unwrap();let name=repo.head().unwrap().name().unwrap().to_owned();repo.find_remote("origin").unwrap().push(&[format!("{name}:{name}")],None).unwrap();(d,work)}
    #[test]fn cached_is_not_remote_proof(){let(_d,w)=fixture();let a=inspect(&w,false).unwrap().unwrap();assert!(!a.all_content_synced);assert!(!a.remote_verified);}
    #[test]fn verify_clean_then_dirty(){let(_d,w)=fixture();let a=inspect(&w,true).unwrap().unwrap();assert!(a.all_content_synced,"{a:?}");std::fs::write(w.join("file.txt"),"new work").unwrap();let a=inspect(&w,true).unwrap().unwrap();assert_eq!(a.modified,1);assert!(!a.all_content_synced);}
    #[test]fn ignored_is_not_synced(){let(_d,w)=fixture();std::fs::write(w.join(".gitignore"),"cache/\n").unwrap();std::fs::create_dir(w.join("cache")).unwrap();std::fs::write(w.join("cache/data"),"local").unwrap();let a=inspect(&w,true).unwrap().unwrap();assert!(a.ignored>0);assert!(!a.all_content_synced);assert!(path_state(&w.join("cache")).unwrap().unwrap().1.contains("ignored"));}
    #[test]fn local_branch_and_tag_are_checked(){let(_d,w)=fixture();let repo=Repository::open(&w).unwrap();let head=repo.head().unwrap().peel_to_commit().unwrap();repo.tag_lightweight("local-tag",head.as_object(),false).unwrap();let a=inspect(&w,true).unwrap().unwrap();assert!(a.local_only_refs.iter().any(|x|x.contains("local-tag")));}
    #[test]fn missing_remote_fails_closed(){let(_d,w)=fixture();Repository::open(&w).unwrap().remote_set_url("origin","Z:/not-a-remote").unwrap();let a=inspect(&w,true).unwrap().unwrap();assert!(!a.remote_verified);assert!(!a.all_content_synced);}
}
