//! Windows Restart Manager, never arbitrary handle injection/closure or SetupAPI.
use anyhow::{Result,bail,ensure};
use serde::Serialize;
use std::path::Path;
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]pub struct Owner{pub pid:u32,pub name:String,pub service:String,pub critical:bool,pub restartable:bool,pub started:u64}
#[cfg(windows)]pub struct Session{handle:u32}
#[cfg(windows)]impl Session{
    pub fn for_file(path:&Path)->Result<Self>{
        use windows_sys::Win32::System::RestartManager::*;
        let mut handle=0;let mut key=[0u16;CCH_RM_SESSION_KEY as usize+1];
        let error=unsafe{RmStartSession(&mut handle,0,key.as_mut_ptr())};ensure!(error==0,"RmStartSession failed ({error})");let session=Self{handle};let wide=crate::platform::wide(path);let resources=[wide.as_ptr()];let error=unsafe{RmRegisterResources(handle,1,resources.as_ptr(),0,std::ptr::null(),0,std::ptr::null())};ensure!(error==0,"RmRegisterResources failed ({error})");Ok(session)
    }
    pub fn owners(&self)->Result<Vec<Owner>>{
        use windows_sys::Win32::{Foundation::ERROR_MORE_DATA,System::RestartManager::*};
        for _ in 0..4{let(mut needed,mut count,mut reasons)=(0,0,0);let code=unsafe{RmGetList(self.handle,&mut needed,&mut count,std::ptr::null_mut(),&mut reasons)};if code==0&&needed==0{return Ok(Vec::new());}ensure!(code==ERROR_MORE_DATA,"RmGetList failed ({code})");ensure!(needed<4096,"unexpected number of file owners");
            let mut infos:Vec<RM_PROCESS_INFO>=(0..needed).map(|_|unsafe{std::mem::zeroed()}).collect();count=needed;let code=unsafe{RmGetList(self.handle,&mut needed,&mut count,infos.as_mut_ptr(),&mut reasons)};if code==ERROR_MORE_DATA{continue;}ensure!(code==0,"RmGetList failed ({code})");
            return Ok(infos.into_iter().take(count as usize).map(|i|{let text=|s:&[u16]|String::from_utf16_lossy(&s[..s.iter().position(|&c|c==0).unwrap_or(s.len())]);Owner{pid:i.Process.dwProcessId,name:text(&i.strAppName),service:text(&i.strServiceShortName),critical:i.ApplicationType==RmCritical||i.ApplicationType==RmService||i.Process.dwProcessId==std::process::id(),restartable:i.bRestartable!=0,started:((i.Process.ProcessStartTime.dwHighDateTime as u64)<<32)|i.Process.ProcessStartTime.dwLowDateTime as u64}}).collect());
        }bail!("file owner set keeps changing")
    }
    /// Must only be called after the UI names the exact owner set and the user agrees.
    pub fn shutdown(&self,shown:&[Owner],force:bool)->Result<()>{
        use windows_sys::Win32::System::RestartManager::*;
        let mut current=self.owners()?;let mut expected=shown.to_vec();current.sort_by_key(|x|(x.pid,x.started));expected.sort_by_key(|x|(x.pid,x.started));ensure!(current==expected,"file owners changed; another confirmation is required");
        ensure!(!current.is_empty(),"Restart Manager could not identify an owner; close it manually and retry");ensure!(current.iter().all(|x|!x.critical),"refusing to shut down critical processes/services/the cleaner itself");
        let code=unsafe{RmShutdown(self.handle,if force{RmForceShutdown as u32}else{0},None)};ensure!(code==0,"Restart Manager shutdown failed ({code}); no manual handle-closing fallback");Ok(())
    }
}
#[cfg(windows)]impl Drop for Session{fn drop(&mut self){unsafe{windows_sys::Win32::System::RestartManager::RmEndSession(self.handle);}}}
#[cfg(not(windows))]pub struct Session;
#[cfg(not(windows))]impl Session{pub fn for_file(_:&Path)->Result<Self>{bail!("Restart Manager is Windows-only")}pub fn owners(&self)->Result<Vec<Owner>>{Ok(Vec::new())}pub fn shutdown(&self,_:&[Owner],_:bool)->Result<()>{bail!("Restart Manager is Windows-only")}}
pub fn error_code(error:&anyhow::Error)->Option<i32>{error.chain().find_map(|e|e.downcast_ref::<std::io::Error>().and_then(|e|e.raw_os_error()))}
pub fn may_be_locked(error:&anyhow::Error)->bool{matches!(error_code(error),Some(5|32|33))}
