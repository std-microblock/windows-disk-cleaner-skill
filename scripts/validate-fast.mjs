// Read-only scans/compares of isolated fixtures. Writes only reports and indexes.
import fs from 'node:fs/promises';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const root=path.resolve(import.meta.dirname,'..');const dir=path.join(root,'validation','artifacts');
const exe=path.join(root,'target','release','disk-cleaner.exe');await fs.mkdir(dir,{recursive:true});
async function run(name,args){const started=Date.now();const p=spawnSync(exe,args,{cwd:root,encoding:'utf8',windowsHide:true,maxBuffer:16*1024*1024,timeout:10*60*1000});
 await fs.writeFile(path.join(dir,name+'.stdout.txt'),p.stdout||'','utf8');await fs.writeFile(path.join(dir,name+'.stderr.txt'),p.stderr||'','utf8');let json;try{json=JSON.parse(p.stdout);}catch{}
 const result={name,args,exit:p.status,wallMs:Date.now()-started,error:p.error?.message,stats:json?.stats,comparison:json?.equal===undefined?undefined:json};console.log(JSON.stringify(result));if(p.status!==0)console.error(p.stderr);return result;}
const doctor=spawnSync(exe,['doctor','--json'],{encoding:'utf8',windowsHide:true});const info=JSON.parse(doctor.stdout);if(!info.administrator)throw Error('Run validation from an administrator context. No auto elevation.');
const results=[];
for(const [name,scope,backend]of [['ntfs',path.join(dir,'ntfs-fixture'),'ntfs'],['refs','E:\\disk-cleaner-fixture','refs']]){
 const fast=path.join(dir,name+'-fast-v3.dcscan'),slow=path.join(dir,name+'-fs-v3.dcscan');
 results.push(await run(name+'-fast',['scan',scope,'--backend',backend,'--threads','8','--no-git','--min-size','0','--depth','1','--save',fast,'--json']));
 results.push(await run(name+'-slow',['scan',scope,'--backend','fs','--threads','8','--no-git','--min-size','0','--depth','1','--save',slow,'--json']));
 if(results.at(-2).exit===0&&results.at(-1).exit===0)results.push(await run(name+'-comparison',['compare',fast,slow,'--scope',scope]));
}
await fs.writeFile(path.join(dir,'fast-validation.json'),JSON.stringify({created:new Date().toISOString(),binarySha256:createHash('sha256').update(await fs.readFile(exe)).digest('hex'),doctor:info,results},null,2),'utf8');
process.exitCode=results.every(r=>r.exit===0)?0:1;
