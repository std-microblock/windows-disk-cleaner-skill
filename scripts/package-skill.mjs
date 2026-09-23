// Packages only built artifacts. Does not install globally or change skill settings.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
const root=path.resolve(import.meta.dirname,'..');
const skill=path.join(root,'skill','windows-disk-cleaner');
const binary=path.join(root,'target','release','disk-cleaner.exe');
const data=await fs.readFile(binary);if(data.subarray(0,2).toString()!=='MZ')throw Error('Not a Windows executable');
await fs.mkdir(path.join(skill,'bin'),{recursive:true});await fs.copyFile(binary,path.join(skill,'bin','disk-cleaner.exe'));
await fs.copyFile(path.join(root,'LICENSE'),path.join(skill,'LICENSE'));
await fs.copyFile(path.join(root,'THIRD_PARTY_NOTICES.md'),path.join(skill,'THIRD_PARTY_NOTICES.md'));
await fs.cp(path.join(root,'licenses'),path.join(skill,'licenses'),{recursive:true});
await fs.writeFile(path.join(skill,'bin','SHA256SUMS'),createHash('sha256').update(data).digest('hex')+'  disk-cleaner.exe\n','utf8');
console.log(JSON.stringify({skill,binaryBytes:data.length,sha256:createHash('sha256').update(data).digest('hex')},null,2));
