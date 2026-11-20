import { createFileRoute, Link } from '@tanstack/react-router';
import { useState, useEffect, useMemo, useRef } from 'react';
import {
  useWorkspace,
  PageHeading,
  Empty,
  getLocalEvidenceBlob,
  getEvidenceCode,
  saveValidationRecord,
  safeRandomUUID,
} from '@/components/deadbyte/workspace';
import { parsePcapForensics } from '@/components/deadbyte/network-analyzer';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import {
  Clock3,
  Download,
  Search,
  Upload,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Filter,
  ArrowUpDown,
  Layers,
  Database,
  Network,
  Image as ImageIcon,
  Archive,
  FolderKanban,
  FileText,
  ArrowUpRight,
} from 'lucide-react';

export const Route = createFileRoute('/timeline')({
  head: () => ({
    meta: [
      { title: 'Investigation Timeline — DeadByte' },
      {
        name: 'description',
        content: 'Unified chronological UTC timeline across all forensic evidence and artifacts.',
      },
      { property: 'og:title', content: 'Investigation Timeline — DeadByte' },
      {
        property: 'og:description',
        content: 'Source-referenced chronological events from your forensic investigations.',
      },
      { property: 'og:type', content: 'website' },
      { name: 'twitter:card', content: 'summary_large_image' },
    ],
  }),
  component: InvestigationTimelinePage,
});

export type TimelineCategory =
  | 'CUSTODY'
  | 'EXIF'
  | 'REGISTRY'
  | 'SQLITE'
  | 'PCAP'
  | 'VALIDATION'
  | 'LOG';

export interface TimelineEvent {
  id: string;
  timestampIso: string;
  epochMs: number;
  caseId: string;
  caseNumber: string;
  evidenceId: string;
  evidenceCode: string;
  filename: string;
  category: TimelineCategory;
  eventType: string;
  summary: string;
  sourceRef: string;
}

function normalizeTimestampToIso(raw: string | number): { iso: string; ms: number } | null {
  if (typeof raw === 'number') {
    // Check WebKit/Chrome timestamp (microseconds since 1601-01-01)
    if (raw > 11644473600000000 && raw < 15000000000000000) {
      const unixMs = Math.round(raw / 1000 - 11644473600000);
      const d = new Date(unixMs);
      if (!isNaN(d.getTime())) return { iso: d.toISOString(), ms: d.getTime() };
    }
    // Unix seconds (1990..2100)
    if (raw > 631152000 && raw < 4102444800) {
      const d = new Date(raw * 1000);
      if (!isNaN(d.getTime())) return { iso: d.toISOString(), ms: d.getTime() };
    }
    // Unix milliseconds
    if (raw > 631152000000 && raw < 4102444800000) {
      const d = new Date(raw);
      if (!isNaN(d.getTime())) return { iso: d.toISOString(), ms: d.getTime() };
    }
    return null;
  }

  const str = String(raw).trim();
  if (!str) return null;

  // EXIF format: "YYYY:MM:DD HH:MM:SS"
  const exifMatch = /^(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/.exec(str);
  if (exifMatch) {
    const isoCandidate = `${exifMatch[1]}-${exifMatch[2]}-${exifMatch[3]}T${exifMatch[4]}:${exifMatch[5]}:${exifMatch[6]}Z`;
    const d = new Date(isoCandidate);
    if (!isNaN(d.getTime())) return { iso: d.toISOString(), ms: d.getTime() };
  }

  // Numeric string check
  if (/^\d{10,17}$/.test(str)) {
    return normalizeTimestampToIso(Number(str));
  }

  const d = new Date(str);
  if (!isNaN(d.getTime()) && d.getFullYear() >= 1990 && d.getFullYear() <= 2100) {
    return { iso: d.toISOString(), ms: d.getTime() };
  }
  return null;
}

async function extractArtifactEventsFromBlob(
  file: File,
  caseId: string,
  caseNumber: string,
  evidenceId: string,
  evidenceCode: string
): Promise<TimelineEvent[]> {
  const events: TimelineEvent[] = [];
  const lower = file.name.toLowerCase();
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);

  // 1. Check if PCAP / PCAPNG
  const view = new DataView(buffer);
  const magicU32 = bytes.length >= 4 ? view.getUint32(0, false) : 0;
  const isPcap =
    magicU32 === 0xd4c3b2a1 ||
    magicU32 === 0xa1b2c3d4 ||
    magicU32 === 0x4d3cb2a1 ||
    magicU32 === 0xa1b23c4d ||
    magicU32 === 0x0a0d0d0a;

  if (isPcap || /\.(pcap|pcapng|cap|dmp)$/i.test(lower)) {
    const pcap = await parsePcapForensics(file);
    if (pcap.isValidCapture) {
      for (const pkt of pcap.packets.slice(0, 60)) {
        if (
          pkt.timestampEpochMs > 0 &&
          (pkt.frameNumber === 1 ||
            pkt.frameNumber === pcap.packets.length ||
            pkt.dnsQuery ||
            pkt.httpMethod ||
            pkt.tlsSni ||
            pkt.suspiciousReason)
        ) {
          events.push({
            id: `${evidenceId}-frame-${pkt.frameNumber}`,
            timestampIso: pkt.timestampIso,
            epochMs: pkt.timestampEpochMs,
            caseId,
            caseNumber,
            evidenceId,
            evidenceCode,
            filename: file.name,
            category: 'PCAP',
            eventType: `Network ${pkt.transportProtocol}`,
            summary: `${pkt.srcIp ?? pkt.srcMac ?? '?'} → ${pkt.dstIp ?? pkt.dstMac ?? '?'} · ${pkt.info}`,
            sourceRef: `${evidenceCode} · Frame #${pkt.frameNumber}`,
          });
        }
      }
    }
    return events;
  }

  // 2. Scan for embedded EXIF timestamps ("20XX:XX:XX XX:XX:XX") in images (.jpg, .png, .heic, .tiff, .webp)
  if (
    /\.(jpg|jpeg|png|heic|heif|tif|tiff|webp)$/i.test(lower) ||
    (bytes[0] === 0xff && bytes[1] === 0xd8) ||
    (bytes[0] === 0x89 && bytes[1] === 0x50)
  ) {
    const maxScan = Math.min(bytes.length, 262144);
    let ascii = '';
    for (let i = 0; i < maxScan; i++) {
      const b = bytes[i] ?? 0;
      ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : ' ';
    }
    const regex = /\b(20\d{2}:\d{2}:\d{2}\s+\d{2}:\d{2}:\d{2})\b/g;
    const seen = new Set<string>();
    let match: RegExpExecArray | null;
    let idx = 0;
    while ((match = regex.exec(ascii)) !== null) {
      const rawTs = match[1] ?? '';
      if (rawTs && !seen.has(rawTs)) {
        seen.add(rawTs);
        const norm = normalizeTimestampToIso(rawTs);
        if (norm) {
          idx++;
          const tagLabel =
            idx === 1 ? 'EXIF DateTime / ModifyDate' : idx === 2 ? 'EXIF DateTimeOriginal' : 'EXIF DateTimeDigitized';
          events.push({
            id: `${evidenceId}-exif-${idx}`,
            timestampIso: norm.iso,
            epochMs: norm.ms,
            caseId,
            caseNumber,
            evidenceId,
            evidenceCode,
            filename: file.name,
            category: 'EXIF',
            eventType: tagLabel,
            summary: `Embedded EXIF timestamp (${rawTs}) extracted from image container ${file.name}.`,
            sourceRef: `${evidenceCode} · EXIF IFD @0x${match.index.toString(16).toUpperCase()}`,
          });
        }
      }
    }
    return events;
  }

  // 3. Check if Windows Registry (.reg text or regf binary hive)
  const isRegf =
    bytes.length >= 4 &&
    bytes[0] === 0x72 &&
    bytes[1] === 0x65 &&
    bytes[2] === 0x67 &&
    bytes[3] === 0x66;
  if (isRegf && bytes.length >= 20) {
    const low = view.getUint32(12, true);
    const high = view.getUint32(16, true);
    const filetime100ns = high * 4294967296 + low;
    const unixMs = Math.round(filetime100ns / 10000 - 11644473600000);
    const norm = normalizeTimestampToIso(unixMs);
    if (norm) {
      events.push({
        id: `${evidenceId}-regf-header`,
        timestampIso: norm.iso,
        epochMs: norm.ms,
        caseId,
        caseNumber,
        evidenceId,
        evidenceCode,
        filename: file.name,
        category: 'REGISTRY',
        eventType: 'Registry Hive LastWritten',
        summary: `Binary regf hive header LastWritten timestamp in ${file.name}.`,
        sourceRef: `${evidenceCode} · regf Header@0x0C`,
      });
    }
  } else if (lower.endsWith('.reg')) {
    const isUtf16 = bytes[0] === 0xff && bytes[1] === 0xfe;
    const text = new TextDecoder(isUtf16 ? 'utf-16le' : 'utf-8').decode(bytes);
    const installMatch = /"InstallDate"=dword:([0-9a-fA-F]{8})/i.exec(text);
    if (installMatch?.[1]) {
      const epochSec = parseInt(installMatch[1], 16);
      const norm = normalizeTimestampToIso(epochSec);
      if (norm) {
        events.push({
          id: `${evidenceId}-reg-install`,
          timestampIso: norm.iso,
          epochMs: norm.ms,
          caseId,
          caseNumber,
          evidenceId,
          evidenceCode,
          filename: file.name,
          category: 'REGISTRY',
          eventType: 'Windows OS InstallDate',
          summary: `Registry CurrentVersion\\InstallDate = 0x${installMatch[1].toUpperCase()} (${epochSec} UTC epoch).`,
          sourceRef: `${evidenceCode} · HKLM\\...\\CurrentVersion\\InstallDate`,
        });
      }
    }
  }

  // 4. Scan SQLite or CSV/JSON/Log files for ISO-8601 timestamps
  const isSqlite =
    bytes.length >= 16 && new TextDecoder('ascii').decode(bytes.subarray(0, 15)) === 'SQLite format 3';
  if (isSqlite || /\.(sqlite|sqlite3|db|csv|json|log|txt)$/i.test(lower)) {
    const maxScan = Math.min(bytes.length, 262144);
    let text = '';
    for (let i = 0; i < maxScan; i++) {
      const b = bytes[i] ?? 0;
      text += b >= 32 && b <= 126 ? String.fromCharCode(b) : '\n';
    }
    const isoRegex = /\b(20\d{2}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\b/g;
    const seen = new Set<string>();
    let match: RegExpExecArray | null;
    let count = 0;
    while ((match = isoRegex.exec(text)) !== null && count < 25) {
      const tsRaw = match[1] ?? '';
      if (tsRaw && !seen.has(tsRaw)) {
        seen.add(tsRaw);
        const norm = normalizeTimestampToIso(tsRaw.includes('T') ? tsRaw : tsRaw.replace(' ', 'T') + 'Z');
        if (norm) {
          count++;
          const contextStart = Math.max(0, match.index - 45);
          const contextEnd = Math.min(text.length, match.index + tsRaw.length + 55);
          const snippet = text
            .slice(contextStart, contextEnd)
            .replace(/\s+/g, ' ')
            .trim();
          events.push({
            id: `${evidenceId}-ts-${count}`,
            timestampIso: norm.iso,
            epochMs: norm.ms,
            caseId,
            caseNumber,
            evidenceId,
            evidenceCode,
            filename: file.name,
            category: isSqlite ? 'SQLITE' : 'LOG',
            eventType: isSqlite ? 'SQLite Record Timestamp' : 'Log Event Timestamp',
            summary: snippet || `Timestamp ${norm.iso} extracted from ${file.name}`,
            sourceRef: `${evidenceCode} · Offset 0x${match.index.toString(16).toUpperCase()}`,
          });
        }
      }
    }
  }

  return events;
}

function InvestigationTimelinePage() {
  const { cases, evidence, activity, validations, refresh } = useWorkspace();
  const [caseFilter, setCaseFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [sortOrder, setSortOrder] = useState<'ASC' | 'DESC'>('ASC');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [artifactEvents, setArtifactEvents] = useState<TimelineEvent[]>([]);
  const [uploadedLogEvents, setUploadedLogEvents] = useState<TimelineEvent[]>([]);
  const [scanning, setScanning] = useState<boolean>(false);
  const logInputRef = useRef<HTMLInputElement>(null);

  // Validation Gate State
  const [externalTool, setExternalTool] = useState<string>('Plaso / log2timeline / Eric Zimmerman Timeline Explorer');
  const [confirmedRange, setConfirmedRange] = useState<string>('');
  const [validatorName, setValidatorName] = useState<string>('Local Investigator');
  const [valNotes, setValNotes] = useState<string>('');

  useEffect(() => {
    let cancelled = false;
    async function scanLockerArtifacts() {
      if (evidence.length === 0) {
        setArtifactEvents([]);
        return;
      }
      setScanning(true);
      const extracted: TimelineEvent[] = [];
      for (const ev of evidence) {
        try {
          const blob = await getLocalEvidenceBlob(ev.storage_path);
          if (!blob) continue;
          const file = new File([blob], ev.filename, { type: ev.file_type || 'application/octet-stream' });
          const c = cases.find((cs) => cs.id === ev.case_id);
          const evCode = getEvidenceCode(ev.id, evidence);
          const evts = await extractArtifactEventsFromBlob(
            file,
            ev.case_id,
            c?.case_number ?? 'DB-LOCAL',
            ev.id,
            evCode
          );
          extracted.push(...evts);
        } catch {
          // continue scanning remaining evidence items
        }
      }
      if (!cancelled) {
        setArtifactEvents(extracted);
        setScanning(false);
      }
    }
    void scanLockerArtifacts();
    return () => {
      cancelled = true;
    };
  }, [evidence, cases]);

  const allEvents = useMemo(() => {
    const list: TimelineEvent[] = [];

    // 1. Case creation events
    for (const c of cases) {
      const norm = normalizeTimestampToIso(c.created_at);
      if (norm) {
        list.push({
          id: `case-${c.id}`,
          timestampIso: norm.iso,
          epochMs: norm.ms,
          caseId: c.id,
          caseNumber: c.case_number,
          evidenceId: 'case-meta',
          evidenceCode: c.case_number,
          filename: c.name,
          category: 'CUSTODY',
          eventType: 'Investigation Case Opened',
          summary: `Case "${c.name}" (${c.case_number}) opened by ${c.investigator || 'Investigator'}.`,
          sourceRef: `Case Record · ${c.case_number}`,
        });
      }
    }

    // 2. Evidence upload intake events
    for (const ev of evidence) {
      const norm = normalizeTimestampToIso(ev.uploaded_at);
      const c = cases.find((cs) => cs.id === ev.case_id);
      const evCode = getEvidenceCode(ev.id, evidence);
      if (norm) {
        list.push({
          id: `ev-upload-${ev.id}`,
          timestampIso: norm.iso,
          epochMs: norm.ms,
          caseId: ev.case_id,
          caseNumber: c?.case_number ?? 'DB-LOCAL',
          evidenceId: ev.id,
          evidenceCode: evCode,
          filename: ev.filename,
          category: 'CUSTODY',
          eventType: 'Evidence Preserved in Locker',
          summary: `${evCode} (${ev.filename}, ${(ev.file_size / 1024).toFixed(1)} KB) preserved with baseline SHA-256 ${ev.sha256.slice(0, 16)}…`,
          sourceRef: `${evCode} · Chain of Custody Intake`,
        });
      }
    }

    // 3. Independent Validation Log events
    for (const v of validations) {
      const norm = normalizeTimestampToIso(v.created_at);
      if (norm) {
        list.push({
          id: `val-${v.id}`,
          timestampIso: norm.iso,
          epochMs: norm.ms,
          caseId: v.case_id,
          caseNumber: v.case_number,
          evidenceId: v.evidence_id,
          evidenceCode: v.evidence_code,
          filename: v.filename,
          category: 'VALIDATION',
          eventType: `${v.module} Validation (${v.status})`,
          summary: `${v.evidence_code} (${v.filename}) verified via ${v.independent_tool}: ${v.independent_result}`,
          sourceRef: `Validation Log · ${v.evidence_code}`,
        });
      }
    }

    // 4. Deep artifact events extracted from preserved binaries
    list.push(...artifactEvents);

    // 5. Directly uploaded log/CSV/JSON events
    list.push(...uploadedLogEvents);

    return list;
  }, [cases, evidence, validations, artifactEvents, uploadedLogEvents]);

  const filteredEvents = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return allEvents
      .filter((e) => {
        if (caseFilter !== 'ALL' && e.caseId !== caseFilter) return false;
        if (categoryFilter !== 'ALL' && e.category !== categoryFilter) return false;
        if (!q) return true;
        return (
          e.timestampIso.toLowerCase().includes(q) ||
          e.evidenceCode.toLowerCase().includes(q) ||
          e.filename.toLowerCase().includes(q) ||
          e.eventType.toLowerCase().includes(q) ||
          e.summary.toLowerCase().includes(q) ||
          e.sourceRef.toLowerCase().includes(q)
        );
      })
      .sort((a, b) => (sortOrder === 'ASC' ? a.epochMs - b.epochMs : b.epochMs - a.epochMs));
  }, [allEvents, caseFilter, categoryFilter, sortOrder, searchQuery]);

  async function handleLogUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const activeCase = cases.find((c) => c.id === caseFilter) ?? cases[0];
      const extracted = await extractArtifactEventsFromBlob(
        file,
        activeCase?.id ?? 'local-case',
        activeCase?.case_number ?? 'DB-LOCAL',
        safeRandomUUID(),
        'E-LOG'
      );
      if (extracted.length === 0) {
        // Fallback: add file lastModified timestamp
        const norm = normalizeTimestampToIso(file.lastModified);
        if (norm) {
          extracted.push({
            id: safeRandomUUID(),
            timestampIso: norm.iso,
            epochMs: norm.ms,
            caseId: activeCase?.id ?? 'local-case',
            caseNumber: activeCase?.case_number ?? 'DB-LOCAL',
            evidenceId: 'standalone-log',
            evidenceCode: 'E-LOG',
            filename: file.name,
            category: 'LOG',
            eventType: 'File LastModified Timestamp',
            summary: `Uploaded file ${file.name} (${file.size.toLocaleString()} bytes) filesystem modification time.`,
            sourceRef: `E-LOG · ${file.name}`,
          });
        }
      }
      setUploadedLogEvents((prev) => [...extracted, ...prev]);
      toast.success(`Extracted ${extracted.length} timestamped event(s) from ${file.name}.`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not parse timestamps from file.');
    } finally {
      e.target.value = '';
    }
  }

  function exportTimelineCsv() {
    if (filteredEvents.length === 0) {
      toast.error('No timeline events to export.');
      return;
    }
    const headers = [
      'UTC_Timestamp',
      'Category',
      'Event_Type',
      'Case_Number',
      'Evidence_ID',
      'Filename',
      'Forensic_Summary',
      'Source_Reference',
    ];
    const rows = filteredEvents.map((ev) =>
      [
        ev.timestampIso,
        ev.category,
        ev.eventType,
        ev.caseNumber,
        ev.evidenceCode,
        ev.filename,
        ev.summary.replace(/"/g, '""'),
        ev.sourceRef.replace(/"/g, '""'),
      ]
        .map((v) => `"${v}"`)
        .join(',')
    );
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `DeadByte_Forensic_Timeline_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast.success('Exported chronological UTC timeline to CSV.');
  }

  async function logTimelineValidation(status: 'VERIFIED' | 'MISMATCH' | 'NEEDS REVIEW') {
    if (filteredEvents.length === 0) {
      toast.error('No timeline events available to validate.');
      return;
    }
    const firstEv = filteredEvents[0];
    const lastEv = filteredEvents[filteredEvents.length - 1];
    const activeCase = cases.find((c) => c.id === caseFilter) ?? cases[0];
    const platformSummary = `${filteredEvents.length} UTC events (${firstEv?.timestampIso ?? 'N/A'} → ${lastEv?.timestampIso ?? 'N/A'})`;

    saveValidationRecord({
      case_id: activeCase?.id ?? 'local-case',
      case_number: activeCase?.case_number ?? 'DB-LOCAL',
      evidence_id: firstEv?.evidenceId ?? 'timeline-correlation',
      evidence_code: firstEv?.evidenceCode ?? 'E-TIMELINE',
      filename: `Cross-Artifact Timeline (${filteredEvents.length} events)`,
      module: 'Timeline',
      algorithm: 'UTC Timestamp Normalization & Ordering',
      platform_result: platformSummary,
      independent_tool: externalTool.trim() || 'Timeline Explorer / CLI',
      independent_result: confirmedRange.trim() || platformSummary,
      status,
      validator: validatorName.trim() || 'Local Investigator',
      notes: valNotes.trim() || 'Verified chronological UTC ordering across case artifacts.',
    });

    await refresh();
    setConfirmedRange('');
    setValNotes('');
    toast.success(`Logged Timeline ${status} entry to the 9-Column Validation Log.`);
  }

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { ALL: allEvents.length };
    for (const e of allEvents) {
      counts[e.category] = (counts[e.category] ?? 0) + 1;
    }
    return counts;
  }, [allEvents]);

  return (
    <div className="page">
      <PageHeading
        eyebrow="MODULE 05 · CROSS-ARTIFACT CORRELATION"
        title="Investigation Timeline"
        description="Unified chronological UTC timeline correlating Chain of Custody, EXIF metadata, Windows Registry, SQLite records, PCAP frames, and log files."
      >
        <input
          ref={logInputRef}
          type="file"
          accept=".csv,.json,.log,.txt,.reg,.sqlite,.db,.pcap,.pcapng,.jpg,.jpeg,.png,.heic"
          className="hidden"
          onChange={handleLogUpload}
        />
        <Button type="button" variant="outline" size="sm" onClick={() => logInputRef.current?.click()}>
          <Upload size={14} /> Import Artifact / Log File
        </Button>
        <Button type="button" variant="default" size="sm" onClick={exportTimelineCsv}>
          <Download size={14} /> Export Timeline CSV
        </Button>
      </PageHeading>

      <div className="hash-analyzer">
        {/* Controls & Filters Bar */}
        <div className="analyzer-controls">
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center', flex: 1 }}>
            <div style={{ minWidth: 200 }}>
              <label htmlFor="timeline-case-filter" className="detail-label" style={{ display: 'block', marginBottom: 4 }}>
                FILTER BY CASE
              </label>
              <select
                id="timeline-case-filter"
                value={caseFilter}
                onChange={(e) => setCaseFilter(e.target.value)}
              >
                <option value="ALL">All Investigations ({cases.length} cases)</option>
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.case_number})
                  </option>
                ))}
              </select>
            </div>

            <div style={{ flex: 1, minWidth: 240 }}>
              <label htmlFor="timeline-search" className="detail-label" style={{ display: 'block', marginBottom: 4 }}>
                SEARCH TIMELINE EVENTS
              </label>
              <div style={{ position: 'relative' }}>
                <Search
                  size={14}
                  style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', opacity: 0.6 }}
                />
                <input
                  id="timeline-search"
                  type="text"
                  placeholder="Search by UTC timestamp, E-001, filename, IP, key path, or Frame #…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{ paddingLeft: 30 }}
                />
              </div>
            </div>

            <div>
              <span className="detail-label" style={{ display: 'block', marginBottom: 4 }}>
                CHRONOLOGICAL ORDER
              </span>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setSortOrder((prev) => (prev === 'ASC' ? 'DESC' : 'ASC'))}
              >
                <ArrowUpDown size={14} />
                {sortOrder === 'ASC' ? 'Oldest → Newest (UTC)' : 'Newest → Oldest (UTC)'}
              </Button>
            </div>
          </div>
        </div>

        {/* Category Filter Pills */}
        <div className="algo-pills" role="tablist" aria-label="Filter timeline by artifact source">
          {(
            [
              ['ALL', 'All Sources'],
              ['CUSTODY', 'Chain of Custody'],
              ['EXIF', 'EXIF / Images'],
              ['REGISTRY', 'Windows Registry'],
              ['SQLITE', 'SQLite Records'],
              ['PCAP', 'Network / PCAP'],
              ['VALIDATION', 'Validations'],
              ['LOG', 'Log Files'],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              className={`algo-pill ${categoryFilter === id ? 'active' : ''}`}
              onClick={() => setCategoryFilter(id)}
            >
              {label} ({categoryCounts[id] ?? 0})
            </button>
          ))}
        </div>

        {scanning && (
          <div className="analyzer-card">
            <p className="mono muted">Scanning preserved evidence binaries for embedded UTC timestamps…</p>
          </div>
        )}

        {filteredEvents.length === 0 && !scanning ? (
          <Empty
            icon={Clock3}
            title="No timeline events match the current filter"
            description="Create a case, upload evidence files in the Evidence Locker, or click 'Import Artifact / Log File' above to correlate timestamps across your investigation."
          >
            <div style={{ display: 'flex', gap: 10 }}>
              <Button asChild variant="outline" size="sm">
                <Link to="/evidence">
                  Open Evidence Locker <ArrowUpRight size={14} />
                </Link>
              </Button>
              <Button type="button" variant="default" size="sm" onClick={() => logInputRef.current?.click()}>
                <Upload size={14} /> Import Artifact / Log File
              </Button>
            </div>
          </Empty>
        ) : (
          <>
            {/* Chronological UTC Timeline Table */}
            <section className="analyzer-card">
              <div className="section-title" style={{ paddingTop: 0 }}>
                <h2>
                  <Clock3 size={17} /> Unified Chronological Event Log (Normalized to UTC)
                  <span className="count-badge">{filteredEvents.length} events</span>
                </h2>
                <span className="subtle-label">SOURCE-ATTRIBUTED</span>
              </div>

              <div className="table-wrap" style={{ maxHeight: 480, overflowY: 'auto' }}>
                <table>
                  <thead>
                    <tr>
                      <th>UTC TIMESTAMP (ISO-8601)</th>
                      <th>SOURCE MODULE</th>
                      <th>EVENT TYPE</th>
                      <th>FORENSIC SUMMARY & ARTIFACT DETAIL</th>
                      <th>SOURCE REFERENCE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvents.map((ev) => (
                      <tr key={ev.id}>
                        <td className="mono" style={{ whiteSpace: 'nowrap', fontSize: '10px' }}>
                          <strong>{ev.timestampIso}</strong>
                        </td>
                        <td>
                          <span className="algo-tag">{ev.category}</span>
                        </td>
                        <td style={{ fontWeight: 600, color: 'var(--foreground)' }}>{ev.eventType}</td>
                        <td className="mono" style={{ fontSize: '10px', maxWidth: 460 }}>
                          {ev.summary}
                        </td>
                        <td className="mono" style={{ fontSize: '10px', whiteSpace: 'nowrap' }}>
                          {ev.sourceRef}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            {/* Independent Timeline Validation Gate */}
            <section className="analyzer-card">
              <div className="section-title" style={{ paddingTop: 0 }}>
                <h2>
                  <ShieldCheck size={17} /> Independent Timeline Validation Gate
                </h2>
                <span className="status-badge status-active">9-COLUMN LOG</span>
              </div>

              <div className="form-row">
                <label className="field-label">
                  External Timeline Tool Used
                  <input
                    type="text"
                    value={externalTool}
                    onChange={(e) => setExternalTool(e.target.value)}
                    placeholder="Timeline Explorer / Plaso / PowerShell Get-ItemProperty"
                  />
                </label>
                <label className="field-label">
                  Confirmed UTC Timestamp or Sequence Output
                  <input
                    type="text"
                    className="mono"
                    value={confirmedRange}
                    onChange={(e) => setConfirmedRange(e.target.value)}
                    placeholder={
                      filteredEvents[0]
                        ? `Confirmed ${filteredEvents[0].timestampIso} (${filteredEvents[0].sourceRef})`
                        : 'Paste external timestamp output'
                    }
                  />
                </label>
              </div>

              <div className="form-row">
                <label className="field-label">
                  Validator (Student Name)
                  <input
                    type="text"
                    value={validatorName}
                    onChange={(e) => setValidatorName(e.target.value)}
                  />
                </label>
                <label className="field-label">
                  Investigator Notes
                  <input
                    type="text"
                    value={valNotes}
                    onChange={(e) => setValNotes(e.target.value)}
                    placeholder="Verified UTC normalization and chronological sequence across artifacts"
                  />
                </label>
              </div>

              <div className="decision-buttons">
                <Button type="button" className="btn-verify" onClick={() => logTimelineValidation('VERIFIED')}>
                  <CheckCircle2 size={15} /> Confirm Timeline VERIFIED
                </Button>
                <Button type="button" variant="destructive" onClick={() => logTimelineValidation('MISMATCH')}>
                  <XCircle size={15} /> Log MISMATCH
                </Button>
                <Button type="button" variant="outline" onClick={() => logTimelineValidation('NEEDS REVIEW')}>
                  <Clock3 size={15} /> Needs Review
                </Button>
              </div>
            </section>
          </>
        )}
      </div>
    </div>
  );
}
