import { createContext, useContext, useEffect, useState, Suspense, type ReactNode } from 'react';
import { Link, useRouterState } from '@tanstack/react-router';
import { useSuspenseQuery, useQueryClient } from '@tanstack/react-query';
import type { User } from '@supabase/supabase-js';
import { supabase } from '@/integrations/supabase/client';
import { lovable } from '@/integrations/lovable/index';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Toaster, toast } from 'sonner';
import { Fingerprint, LayoutDashboard, FolderKanban, Archive, Hash, Image, Network, Database, Bot, Clock3, ShieldCheck, FileText, Settings, ChevronDown, ChevronRight, Bell, Search, Menu, X, LogOut, Terminal, LockKeyhole, ArrowUpRight, Layers, Users } from 'lucide-react';
import type { Database as DB } from '@/integrations/supabase/types';
export type Case = DB['public']['Tables']['cases']['Row'];
export type Evidence = DB['public']['Tables']['evidence']['Row'];
export type Activity = DB['public']['Tables']['activity']['Row'];
export type ValidationStatus = 'UNPROCESSED' | 'PROCESSED' | 'VERIFIED' | 'MISMATCH' | 'NEEDS REVIEW' | 'REJECTED';
export interface ValidationRecord {
  id: string;
  case_id: string;
  case_number: string;
  evidence_id: string;
  evidence_code: string;
  filename: string;
  module: 'Hash' | 'EXIF' | 'Registry' | 'PCAP' | 'SQLite' | 'Timeline';
  algorithm?: string;
  platform_result: string;
  independent_tool: string;
  independent_result: string;
  status: 'VERIFIED' | 'MISMATCH' | 'NEEDS REVIEW';
  validator: string;
  created_at: string;
  notes: string;
}
const LOCAL_KEYS = {
  cases: 'deadbyte_local_cases',
  evidence: 'deadbyte_local_evidence',
  activity: 'deadbyte_local_activity',
  validations: 'deadbyte_local_validations',
} as const;
function readLocal<T>(key: string): T[] {
  if (typeof window === 'undefined') return [];
  try { return JSON.parse(window.localStorage.getItem(key) || '[]') as T[]; } catch { return []; }
}
function writeLocal<T>(key: string, items: T[]) {
  if (typeof window !== 'undefined') window.localStorage.setItem(key, JSON.stringify(items));
}
export function safeRandomUUID(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}
export function computeSha256Pure(buffer: ArrayBuffer): string {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  const input = new Uint8Array(buffer);
  const bitLen = input.length * 8;
  const padLen = ((input.length + 9 + 63) >> 6) << 6;
  const padded = new Uint8Array(padLen);
  padded.set(input);
  padded[input.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(padLen - 4, bitLen >>> 0, false);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const W = new Uint32Array(64);

  for (let offset = 0; offset < padLen; offset += 64) {
    for (let i = 0; i < 16; i++) W[i] = view.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const w15 = W[i - 15] ?? 0;
      const w2 = W[i - 2] ?? 0;
      const s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >>> 3);
      const s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >>> 10);
      W[i] = ((W[i - 16] ?? 0) + s0 + (W[i - 7] ?? 0) + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + (K[i] ?? 0) + (W[i] ?? 0)) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6, h7].map(v => v.toString(16).padStart(8, '0')).join('');
}
export async function safeSha256Hex(buffer: ArrayBuffer): Promise<string> {
  if (typeof crypto !== 'undefined' && crypto.subtle && typeof crypto.subtle.digest === 'function') {
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
  return computeSha256Pure(buffer);
}
export function getEvidenceCode(evidenceId: string, allEvidence: Evidence[]): string {
  const sorted = [...allEvidence].sort((a, b) => new Date(a.uploaded_at).getTime() - new Date(b.uploaded_at).getTime());
  const index = sorted.findIndex(e => e.id === evidenceId);
  return index >= 0 ? `E-${String(index + 1).padStart(3, '0')}` : `E-${evidenceId.slice(0, 4).toUpperCase()}`;
}
export function saveLocalCase(values: { name: string; description: string; investigator: string; notes: string; status: string }, existingId?: string) {
  const cases = readLocal<Case>(LOCAL_KEYS.cases);
  const activity = readLocal<Activity>(LOCAL_KEYS.activity);
  const now = new Date().toISOString();
  let targetId = existingId;
  if (existingId) {
    const idx = cases.findIndex(c => c.id === existingId);
    if (idx !== -1) cases[idx] = { ...cases[idx], ...values };
  } else {
    targetId = safeRandomUUID();
    const caseNumber = 'DB-' + targetId.replace(/-/g, '').slice(0, 8).toUpperCase();
    cases.unshift({ id: targetId, case_number: caseNumber, owner_id: 'local-investigator', created_at: now, ...values });
  }
  if (targetId) {
    activity.unshift({ id: safeRandomUUID(), owner_id: 'local-investigator', case_id: targetId, action: existingId ? 'Case updated' : 'Case created', detail: values.name, created_at: now });
  }
  writeLocal(LOCAL_KEYS.cases, cases);
  writeLocal(LOCAL_KEYS.activity, activity.slice(0, 100));
}
function openBlobDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('deadbyte_files', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('blobs');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
export async function saveLocalEvidence(record: Evidence, file: File) {
  const db = await openBlobDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction('blobs', 'readwrite');
    tx.objectStore('blobs').put(file, record.storage_path);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  const evidence = readLocal<Evidence>(LOCAL_KEYS.evidence);
  const activity = readLocal<Activity>(LOCAL_KEYS.activity);
  evidence.unshift(record);
  const evCode = getEvidenceCode(record.id, evidence);
  activity.unshift({ id: safeRandomUUID(), owner_id: 'local-investigator', case_id: record.case_id, action: 'Evidence uploaded', detail: `${evCode} · ${record.filename}`, created_at: record.uploaded_at });
  writeLocal(LOCAL_KEYS.evidence, evidence);
  writeLocal(LOCAL_KEYS.activity, activity.slice(0, 100));
}
export function markLocalEvidenceProcessed(evidenceId: string) {
  const evidence = readLocal<Evidence>(LOCAL_KEYS.evidence);
  const idx = evidence.findIndex(e => e.id === evidenceId);
  if (idx === -1) return false;
  if (evidence[idx].processing_status === 'UNPROCESSED') {
    evidence[idx] = {
      ...evidence[idx],
      processing_status: 'PROCESSED',
      validation_status: evidence[idx].validation_status === 'UNPROCESSED' ? 'PROCESSED' : evidence[idx].validation_status,
    };
    writeLocal(LOCAL_KEYS.evidence, evidence);
    return true;
  }
  return false;
}
export function saveValidationRecord(input: Omit<ValidationRecord, 'id' | 'created_at'>): ValidationRecord {
  const validations = readLocal<ValidationRecord>(LOCAL_KEYS.validations);
  const evidence = readLocal<Evidence>(LOCAL_KEYS.evidence);
  const activity = readLocal<Activity>(LOCAL_KEYS.activity);
  const now = new Date().toISOString();
  const record: ValidationRecord = {
    ...input,
    id: safeRandomUUID(),
    created_at: now,
  };
  validations.unshift(record);
  writeLocal(LOCAL_KEYS.validations, validations);

  const idx = evidence.findIndex(e => e.id === input.evidence_id);
  if (idx !== -1) {
    evidence[idx] = {
      ...evidence[idx],
      processing_status: 'PROCESSED',
      validation_status: input.status,
    };
    writeLocal(LOCAL_KEYS.evidence, evidence);
  }

  const actionLabel =
    input.status === 'VERIFIED'
      ? `${input.module} verified (${input.independent_tool})`
      : input.status === 'MISMATCH'
        ? `${input.module} MISMATCH (${input.independent_tool})`
        : `${input.module} flagged NEEDS REVIEW`;

  activity.unshift({
    id: safeRandomUUID(),
    owner_id: 'local-investigator',
    case_id: input.case_id,
    action: actionLabel,
    detail: `${input.evidence_code} · ${input.filename} · Validator: ${input.validator}${input.notes ? ` — ${input.notes}` : ''}`,
    created_at: now,
  });
  writeLocal(LOCAL_KEYS.activity, activity.slice(0, 100));
  return record;
}
export function updateLocalEvidenceStatus(evidenceId: string, validationStatus: 'VERIFIED' | 'MISMATCH' | 'UNPROCESSED' | 'NEEDS REVIEW' | 'PROCESSED', note?: string) {
  const evidence = readLocal<Evidence>(LOCAL_KEYS.evidence);
  const activity = readLocal<Activity>(LOCAL_KEYS.activity);
  const idx = evidence.findIndex(e => e.id === evidenceId);
  if (idx === -1) return;
  const item = evidence[idx];
  evidence[idx] = {
    ...item,
    validation_status: validationStatus,
    processing_status: validationStatus === 'UNPROCESSED' ? 'UNPROCESSED' : 'PROCESSED',
  };
  const now = new Date().toISOString();
  const actionLabel = validationStatus === 'VERIFIED' ? 'Evidence verified' : validationStatus === 'MISMATCH' ? 'Hash mismatch flagged' : 'Validation updated';
  activity.unshift({
    id: safeRandomUUID(),
    owner_id: 'local-investigator',
    case_id: item.case_id,
    action: actionLabel,
    detail: note ? `${item.filename} — ${note}` : item.filename,
    created_at: now,
  });
  writeLocal(LOCAL_KEYS.evidence, evidence);
  writeLocal(LOCAL_KEYS.activity, activity.slice(0, 100));
}
export async function getLocalEvidenceBlob(storagePath: string): Promise<Blob | undefined> {
  const db = await openBlobDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction('blobs', 'readonly');
    const req = tx.objectStore('blobs').get(storagePath);
    req.onsuccess = () => resolve(req.result as Blob | undefined);
    req.onerror = () => reject(req.error);
  });
}
const Context = createContext<{user:User|null; cases:Case[]; evidence:Evidence[]; activity:Activity[]; validations:ValidationRecord[]; openAuth:()=>void; refresh:()=>Promise<void>}>({user:null,cases:[],evidence:[],activity:[],validations:[],openAuth:()=>{},refresh:async()=>{}});
export const useWorkspace = () => useContext(Context);
export function Brand(){return <div className="brand"><div className="brand-mark"><Fingerprint size={29}/></div><div><span className="brand-name">Dead<span>Byte</span><span className="brand-dot">.</span></span><div className="brand-sub">DIGITAL FORENSICS</div></div></div>}
function Records({user, children,openAuth,validations}:{user:User;children:ReactNode;openAuth:()=>void;validations:ValidationRecord[]}){
 const qc=useQueryClient();
 const {data}=useSuspenseQuery({queryKey:['workspace',user.id],queryFn:async()=>{const [c,e,a]=await Promise.all([supabase.from('cases').select('*').order('created_at',{ascending:false}),supabase.from('evidence').select('*').order('uploaded_at',{ascending:false}),supabase.from('activity').select('*').order('created_at',{ascending:false}).limit(100)]);for(const r of [c,e,a])if(r.error)throw r.error;return {cases:c.data??[],evidence:e.data??[],activity:a.data??[]};}});
  return <Context.Provider value={{user,...data,validations,openAuth,refresh:async()=>{await qc.invalidateQueries({queryKey:['workspace']});}}}>{children}</Context.Provider>;
}
export function Workspace({children}:{children:ReactNode}){
 const [user,setUser]=useState<User|null>(null),[auth,setAuth]=useState(false),[mode,setMode]=useState<'signin'|'signup'|'reset'>('signin'),[busy,setBusy]=useState(false),[mobile,setMobile]=useState(false),[search,setSearch]=useState(''),[alerts,setAlerts]=useState(false);
 const [localData,setLocalData]=useState<{cases:Case[];evidence:Evidence[];activity:Activity[];validations:ValidationRecord[]}>({cases:[],evidence:[],activity:[],validations:[]});
 const loadLocal=()=>{setLocalData({cases:readLocal<Case>(LOCAL_KEYS.cases),evidence:readLocal<Evidence>(LOCAL_KEYS.evidence),activity:readLocal<Activity>(LOCAL_KEYS.activity),validations:readLocal<ValidationRecord>(LOCAL_KEYS.validations)});};
 const qc=useQueryClient(); const path=useRouterState({select:s=>s.location.pathname});
 useEffect(()=>{loadLocal();supabase.auth.getUser().then(({data})=>setUser(data.user)).catch(()=>{});const {data}=supabase.auth.onAuthStateChange((event,session)=>{if(['SIGNED_IN','SIGNED_OUT','USER_UPDATED','INITIAL_SESSION'].includes(event)){setUser(session?.user??null);if(event==='SIGNED_IN'){setAuth(false);qc.invalidateQueries({queryKey:['workspace']});}if(event==='SIGNED_OUT')qc.removeQueries({queryKey:['workspace']});}});return()=>data.subscription.unsubscribe();},[qc]);
 useEffect(()=>{setMobile(false);},[path]);
 async function submit(e:React.FormEvent<HTMLFormElement>){e.preventDefault();setBusy(true);const f=new FormData(e.currentTarget),email=String(f.get('email')),password=String(f.get('password'));try{if(mode==='reset'){const {error}=await supabase.auth.resetPasswordForEmail(email,{redirectTo:window.location.origin+'/settings'});if(error)throw error;toast.success('Password reset email sent.');}else if(mode==='signup'){const {error}=await supabase.auth.signUp({email,password,options:{emailRedirectTo:window.location.origin}});if(error)throw error;toast.success('Check your email to confirm your account.');}else{const {error}=await supabase.auth.signInWithPassword({email,password});if(error)throw error;setAuth(false);}}catch(e){toast.error(e instanceof Error?e.message:'Sign-in failed.');}finally{setBusy(false);}}
 const nav=[{label:'Team Biography',to:'/team',icon:Users},{label:'Dashboard',to:'/',icon:LayoutDashboard},{label:'Case Manager',to:'/cases',icon:FolderKanban},{label:'Evidence Locker',to:'/evidence',icon:Archive}] as const;
 const tools=[['hash','Hash Analyzer',Hash],['exif','EXIF Analyzer',Image],['registry','Windows Registry',Layers],['network','Network / PCAP',Network],['sqlite','SQLite Analyzer',Database],['copilot','AI Forensic Copilot',Bot]] as const;
 const chrome=<div className="app-shell"><aside className={`sidebar ${mobile?'sidebar-open':''}`}><Link to="/" className="brand-link"><Brand/></Link><div className="workspace-label"><span className="workspace-icon"><Terminal size={16}/></span><div>DeadByte Workspace<small>NWIT 263 · Fall 2026</small></div><ChevronDown size={14}/></div><div className="nav-caption">WORKSPACE</div><nav>{nav.map(n=><Link key={n.to} to={n.to} className="nav-item" activeProps={{className:'nav-item active'}} activeOptions={{exact:true}}><n.icon size={18}/><span>{n.label}</span>{n.to==='/'&&<span className="nav-active-dot"/>}</Link>)}</nav><div className="nav-caption">FORENSIC TOOLKIT <span>06</span></div><nav>{tools.map(([id,label,Icon])=><Link key={id} to="/tools/$tool" params={{tool:id}} className={`nav-item ${id==='copilot'?'copilot-nav':''}`}><Icon size={18}/><span>{label}</span>{id==='copilot'&&<span className="ai-label">AI</span>}</Link>)}</nav><div className="nav-caption">INVESTIGATION</div><nav><Link to="/timeline" className="nav-item"><Clock3 size={18}/>Investigation Timeline</Link><Link to="/validation" className="nav-item"><ShieldCheck size={18}/>Validation Log</Link><Link to="/reports" className="nav-item"><FileText size={18}/>Reports</Link></nav><div className="sidebar-bottom"><div className="secure-note"><ShieldCheck size={16}/><div>Evidence stays private<small>Original files preserved</small></div><span className="live-dot"/></div><Link to="/settings" className="nav-item"><Settings size={18}/>Settings</Link><div className="account"><div className="avatar">{user?user.email?.slice(0,2).toUpperCase():'DB'}</div><div className="account-copy">{user?user.email?.split('@')[0]:'Local investigator'}<small>{user?'Personal workspace':'Local workspace'}</small></div><Button variant="ghost" size="icon" title={user?'Sign out':'Sign in'} aria-label={user?'Sign out':'Sign in'} onClick={()=>user?supabase.auth.signOut():setAuth(true)}>{user?<LogOut/>:<ArrowUpRight/>}</Button></div></div></aside>{mobile&&<div className="mobile-scrim" onClick={()=>setMobile(false)}/>}
 <div className="main-shell"><header className="topbar"><div className="breadcrumb"><Button className="mobile-menu" variant="ghost" size="icon" aria-label="Open navigation" onClick={()=>setMobile(!mobile)}><Menu/></Button><span>Workspace</span><ChevronRight size={13}/><strong>{path==='/'?'Dashboard':path==='/team'?'Team Biography':path.startsWith('/tools')?'Forensic Toolkit':path==='/cases'?'Case Manager':path==='/evidence'?'Evidence Locker':path.slice(1).replace(/^./,c=>c.toUpperCase())}</strong></div><div className="top-actions"><span className="environment"><span className="live-dot"/> PRIVATE WORKSPACE</span><div className="header-divider"/><Button variant="ghost" size="icon" title="Search cases" aria-label="Search cases" onClick={()=>setSearch(' ')}><Search/></Button><Button variant="ghost" size="icon" title="System alerts" aria-label="System alerts" onClick={()=>setAlerts(true)}><Bell/></Button><div className="avatar small">{user?user.email?.slice(0,2).toUpperCase():'DB'}</div></div></header><main>{children}</main><footer><span><LockKeyhole size={12}/> Authorized evidence only</span><span>DeadByte <span className="footer-dot">·</span> NWIT 263 <span className="footer-dot">·</span> Fall 2026</span><span className="footer-build">PHASE 01 <span className="live-dot"/></span></footer></div>
 <Dialog open={auth} onOpenChange={setAuth}><DialogContent><DialogHeader><DialogTitle>{mode==='signup'?'Create investigator account':mode==='reset'?'Reset your password':'Access your workspace'}</DialogTitle></DialogHeader><p className="dialog-description">DeadByte · Every Byte Leaves a Trace.</p><form className="form-stack" onSubmit={submit}><label>Email<input name="email" type="email" required autoComplete="email" placeholder="you@college.edu"/></label>{mode!=='reset'&&<label>Password<input name="password" type="password" minLength={8} required autoComplete={mode==='signup'?'new-password':'current-password'}/></label>}<Button disabled={busy} type="submit">{busy?'Please wait…':mode==='signup'?'Create account':mode==='reset'?'Send reset link':'Sign in'}<ArrowUpRight/></Button></form>{mode!=='reset'&&<Button variant="outline" onClick={async()=>{const r=await lovable.auth.signInWithOAuth('google',{redirect_uri:window.location.origin});if(r.error)toast.error(r.error.message);}}>Continue with Google</Button>}<div className="auth-switch"><Button variant="link" onClick={()=>setMode(mode==='signup'?'signin':'signup')}>{mode==='signup'?'Already have an account? Sign in':'Create an account'}</Button><Button variant="link" onClick={()=>setMode(mode==='reset'?'signin':'reset')}>{mode==='reset'?'Back to sign in':'Forgot password?'}</Button></div></DialogContent></Dialog>
 <Dialog open={!!search} onOpenChange={v=>!v&&setSearch('')}><DialogContent><DialogHeader><DialogTitle>Search investigations</DialogTitle></DialogHeader><input aria-label="Search investigations" placeholder="Search case names or IDs…" value={search.trimStart()} onChange={e=>setSearch(e.target.value||' ')}/><SearchResults search={search}/></DialogContent></Dialog><Dialog open={alerts} onOpenChange={setAlerts}><DialogContent><DialogHeader><DialogTitle>System alerts</DialogTitle></DialogHeader><div className="empty-small"><ShieldCheck size={32}/><h3>No system alerts</h3><p>Phase 1 workspace. Evidence analysis is not enabled yet.</p></div></DialogContent></Dialog><Toaster theme="dark" richColors position="bottom-right"/></div>;
 return user?<Suspense fallback={<div className="loading-screen"><Fingerprint/><span>Opening secure workspace…</span></div>}><Records user={user} validations={localData.validations} openAuth={()=>setAuth(true)}>{chrome}</Records></Suspense>:<Context.Provider value={{user:null,...localData,openAuth:()=>setAuth(true),refresh:async()=>{loadLocal();}}}>{chrome}</Context.Provider>;
}
function SearchResults({search}:{search:string}){const {cases}=useWorkspace();const list=cases.filter(c=>(c.name+c.case_number).toLowerCase().includes(search.trim().toLowerCase()));return <div className="search-results">{list.length?list.map(c=><Link key={c.id} to="/cases" search={{case:c.id}}>{c.name}<small>{c.case_number}</small></Link>):<p className="muted">No matching cases.</p>}</div>}
export function Empty({icon:Icon,title,description,children}:{icon:typeof FolderKanban;title:string;description:string;children?:ReactNode}){return <div className="empty-state"><div className="empty-icon"><Icon size={26}/></div><h3>{title}</h3><p>{description}</p>{children}</div>}
export function PageHeading({eyebrow,title,description,children}:{eyebrow?:string;title:string;description:string;children?:ReactNode}){return <div className="page-heading"><div>{eyebrow&&<div className="eyebrow">{eyebrow}</div>}<h1>{title}</h1><p>{description}</p></div><div className="heading-actions">{children}</div></div>}
