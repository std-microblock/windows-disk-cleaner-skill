// Creates only isolated test fixtures. Never removes or overwrites existing content.
import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
const workspace = path.resolve(import.meta.dirname, '..');
const volumes = [
  { filesystem: 'NTFS', root: path.join(workspace, 'validation', 'artifacts', 'ntfs-fixture') },
  { filesystem: 'ReFS', root: 'E:\\disk-cleaner-fixture' },
];
const count = Number(process.argv[2] || 25000);
if (!Number.isSafeInteger(count) || count < 1 || count > 100000) throw Error('count must be 1..100000');
const results=[];
for (const volume of volumes) {
  const root=path.resolve(volume.root);
  if (!(root.startsWith(workspace+path.sep) || root==='E:\\disk-cleaner-fixture')) throw Error('outside fixture scope');
  await fs.mkdir(root,{recursive:true});
  const marker=path.join(root,'.disk-cleaner-test-fixture');
  try { await fs.writeFile(marker,'disk-cleaner-owned-fixture/v1\n',{flag:'wx'}); }
  catch(e) { if(e.code!=='EEXIST'||await fs.readFile(marker,'utf8')!=='disk-cleaner-owned-fixture/v1\n') throw e; }
  async function write(relative,buffer) { const p=path.join(root,relative);try{await fs.writeFile(p,buffer,{flag:'wx'});}catch(e){if(e.code!=='EEXIST'||(await fs.stat(p)).size!==buffer.length)throw e;} }
  for(let i=0;i<128;i++)await fs.mkdir(path.join(root,'shards',String(i).padStart(3,'0')),{recursive:true});
  await fs.mkdir(path.join(root,'edge-cases','empty-directory'),{recursive:true});
  let next=0;const started=Date.now();
  await Promise.all(Array.from({length:8},async()=>{while(next<count){const i=next++;const size=i%11===0?0:1024+(i*97)%7168;await write(path.join('shards',String(i%128).padStart(3,'0'),String(i).padStart(6,'0')+'.bin'),Buffer.alloc(size,i%251));}}));
  await write('edge-cases/中文与🚀.txt',Buffer.from('UTF-16 filename round-trip; metadata only.\n'));
  await write('edge-cases/shared.bin',Buffer.alloc(32768,0x41));
  let hardlinks='created';try{await fs.link(path.join(root,'edge-cases/shared.bin'),path.join(root,'edge-cases/shared-alias.bin'));}catch(e){if(e.code!=='EEXIST'){hardlinks=e.code;}}
  await write('edge-cases/stream-host.bin',Buffer.alloc(2048,0x42));
  let ads='created';try{await write('edge-cases/stream-host.bin:review-test',Buffer.alloc(65536,0x43));}catch(e){ads=e.code;}
  await write('large-file.bin',Buffer.alloc(16*1024*1024,0x54));
  const sparse=path.join(root,'edge-cases','sparse.bin');
  try{const h=await fs.open(sparse,'wx');await h.close();const result=spawnSync('fsutil.exe',['sparse','setflag',sparse],{encoding:'utf8',windowsHide:true});if(result.status!==0)throw Error(result.stdout+result.stderr);const f=await fs.open(sparse,'r+');await f.truncate(128*1024*1024);await f.write(Buffer.alloc(4096,0x45),0,4096,4096);await f.write(Buffer.alloc(4096,0x46),0,4096,128*1024*1024-4096);await f.close();}catch(e){if(e.code!=='EEXIST')throw e;}
  let compression='not requested on ReFS';
  if(volume.filesystem==='NTFS'){await write('edge-cases/compressed.bin',Buffer.alloc(2*1024*1024,0x31));const result=spawnSync('compact.exe',['/C','/I','/Q',path.join(root,'edge-cases/compressed.bin')],{encoding:'utf8',windowsHide:true});compression=result.status===0?'compressed':result.stdout+result.stderr;}
  const outside=path.join(path.dirname(root),path.basename(root)+'-outside-canary');await fs.mkdir(outside,{recursive:true});try{await fs.writeFile(path.join(outside,'DO-NOT-FOLLOW.txt'),'outside the scan/delete fixture\n',{flag:'wx'});}catch(e){if(e.code!=='EEXIST')throw e;}
  let junction='created';try{await fs.symlink(outside,path.join(root,'edge-cases','junction-to-outside'),'junction');}catch(e){if(e.code!=='EEXIST')junction=e.code;}
  const result={...volume,smallFiles:count,hardlinks,ads,compression,junction,creationMs:Date.now()-started};results.push(result);console.log(result);
}
await fs.writeFile(path.join(workspace,'validation','artifacts','fixtures.json'),JSON.stringify({created:new Date().toISOString(),volumes:results},null,2),'utf8');
