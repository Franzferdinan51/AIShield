#!/usr/bin/env python3
"""v0.17.2 fix: target selects on Scan/Patch pages were inert.
1) loadStatus rebuilt both selects' innerHTML, resetting the selection.
2) Neither select had a change handler — the Patch plan only loaded on
   entering the view, so picking another target changed nothing on screen.
Fix: preserve selections across rebuilds; wire change handlers
(patch -> loadPlan, scan -> clear stale results of the previous target).
"""
import pathlib

p = pathlib.Path("aishield/gui.py")
src = p.read_text()
n0 = src

old_opts = """ const opts=STATUS.targets.map(t=>`<option>${esc(t)}</option>`).join('');
 $('#scan-target').innerHTML=opts; $('#patch-target').innerHTML=opts; const _nwt=$('#nw-target'); if(_nwt)_nwt.innerHTML=opts;"""
new_opts = """ const opts=STATUS.targets.map(t=>`<option>${esc(t)}</option>`).join('');
 const _keep={}; for(const _id of ['scan-target','patch-target','nw-target']){const _e=document.getElementById(_id); if(_e&&_e.value)_keep[_id]=_e.value;}
 $('#scan-target').innerHTML=opts; $('#patch-target').innerHTML=opts; const _nwt=$('#nw-target'); if(_nwt)_nwt.innerHTML=opts;
 for(const _id of ['scan-target','patch-target','nw-target']){const _e=document.getElementById(_id); if(_e&&_keep[_id]&&STATUS.targets.includes(_keep[_id]))_e.value=_keep[_id];}"""
assert src.count(old_opts) == 1, "opts anchor"
src = src.replace(old_opts, new_opts)

anchor = "$('#scan-filter').addEventListener('input',renderScan);"
assert src.count(anchor) == 1, "binding anchor"
handlers = anchor + """
$('#patch-target').addEventListener('change',()=>{loadPlan();});
$('#scan-target').addEventListener('change',()=>{LASTSCAN=null;$('#scan-out').innerHTML='';$('#scan-filter-row').style.display='none';$('#scan-state').textContent='target changed — press Scan';});"""
src = src.replace(anchor, handlers)

assert src != n0 and src.count("addEventListener('change',()=>{loadPlan();})") == 1
p.write_text(src)
print("gui.py patched OK")
