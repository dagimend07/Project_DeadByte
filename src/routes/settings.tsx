import { createFileRoute } from '@tanstack/react-router';
import { useState } from 'react';
import { PageHeading,useWorkspace } from '@/components/deadbyte/workspace';
import { Button } from '@/components/ui/button';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { LockKeyhole,LogOut } from 'lucide-react';
import { ThemePicker } from '@/components/deadbyte/theme-picker';
export const Route=createFileRoute('/settings')({head:()=>({meta:[{title:'Workspace Settings — DeadByte'},{name:'description',content:'Manage your DeadByte investigator account and private workspace.'},{property:'og:title',content:'Workspace Settings — DeadByte'},{property:'og:description',content:'Investigator account and evidence privacy settings.'},{property:'og:type',content:'website'},{name:'twitter:card',content:'summary_large_image'}]}),component:Settings});
function Settings(){return <div className="page"><PageHeading eyebrow="WORKSPACE" title="Settings" description="Your workspace appearance and evidence safeguards."/><div className="settings-row"><div><h3>Appearance</h3><p>Choose light or dark mode and an accent color. Saved on this device.</p></div><ThemePicker/></div><div className="settings-row"><div><h3>Evidence security</h3><p>Private original storage · Investigator-owned case access · No overwrites</p></div><span className="status-badge status-active">ENABLED</span></div><div className="settings-row"><div><h3>Investigation timezone</h3><p>Timestamps are stored in UTC and shown in your browser’s local timezone.</p></div><span className="mono muted">UTC storage</span></div></div>}
