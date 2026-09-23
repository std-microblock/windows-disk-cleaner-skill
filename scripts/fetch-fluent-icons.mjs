// Fetch selected official Fluent System Icons, preserving the MIT license.
// Run explicitly when updating UI assets; no network access during build/runtime.
import fs from 'node:fs/promises';
import path from 'node:path';
const root=path.resolve(import.meta.dirname,'..');
const repository='microsoft/fluentui-system-icons';
async function fetchText(url){for(let retry=0;retry<3;retry++){try{const r=await fetch(url);if(!r.ok)throw Error(url+' HTTP '+r.status);return await r.text();}catch(e){if(retry===2)throw e;}}}
const pin=process.argv[2]||JSON.parse(await fetchText('https://api.github.com/repos/'+repository+'/commits/main')).sha;
const icons={drive:'Hard Drive',folder:'Folder','folder-open':'Folder Open',file:'Document',code:'Code',text:'Document Text',archive:'Archive',settings:'Settings',image:'Image',video:'Video',audio:'Music Note 1',link:'Link',refresh:'Arrow Clockwise',git:'Branch',select:'Checkbox Checked',deselect:'Checkbox Unchecked',unmark:'Dismiss Square',delete:'Delete',warning:'Warning',close:'Dismiss',check:'Checkmark','chevron-down':'Chevron Down','chevron-right':'Chevron Right',add:'Add'};
const dir=path.join(root,'ui','icons','fluent');await fs.mkdir(dir,{recursive:true});
for(const [local,name]of Object.entries(icons)){
  const source='assets/'+encodeURIComponent(name)+'/SVG/ic_fluent_'+name.toLowerCase().replaceAll(' ','_')+'_20_regular.svg';
  try{const text=await fetchText('https://raw.githubusercontent.com/'+repository+'/'+pin+'/'+source);await fs.writeFile(path.join(dir,local+'.svg'),text,'utf8');console.log(local);}catch(e){console.error(e.message);process.exitCode=1;}
}
await fs.writeFile(path.join(dir,'LICENSE'),await fetchText('https://raw.githubusercontent.com/'+repository+'/'+pin+'/LICENSE'),'utf8');
await fs.writeFile(path.join(dir,'NOTICE.md'),'Selected, unmodified 20px regular Fluent System Icons.\nCopyright Microsoft Corporation. Licensed under MIT (see LICENSE).\nUpstream: https://github.com/'+repository+'\nRevision: '+pin+'\n\nOnly recolored/scaled at runtime; original SVG paths retained.\n','utf8');
console.log('revision',pin);
