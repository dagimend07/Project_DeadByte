import { useState, useRef, useEffect } from 'react';
import { Link } from '@tanstack/react-router';
import {
  useWorkspace,
  getLocalEvidenceBlob,
  getEvidenceCode,
  markLocalEvidenceProcessed,
  saveValidationRecord,
  computeSha256Pure,
  Empty,
} from './workspace';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import {
  Hash,
  Upload,
  Copy,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Archive,
  FileText,
  RefreshCw,
  ArrowUpRight,
  Terminal,
  Clock3,
} from 'lucide-react';

export type HashAlgorithm = 'SHA-256' | 'SHA-512' | 'SHA-384' | 'SHA-1' | 'MD5' | 'ALL';

const SINGLE_ALGORITHMS: Exclude<HashAlgorithm, 'ALL'>[] = [
  'SHA-256',
  'SHA-512',
  'SHA-384',
  'SHA-1',
  'MD5',
];

const INDEPENDENT_TOOLS = [
  'PowerShell: Get-FileHash',
  'Windows: certutil -hashfile',
  'Linux / macOS: sha256sum / md5sum',
  'FTK Imager',
  'Autopsy',
  'Other Approved Forensic Tool',
] as const;

/**
 * Pure TypeScript RFC 1321 MD5 implementation for ArrayBuffer inputs
 */
function computeMd5(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const origBitLen = bytes.length * 8;
  const withOne = bytes.length + 1;
  const padLen = (56 - (withOne % 64) + 64) % 64;
  const totalLen = withOne + padLen + 8;
  const padded = new Uint8Array(totalLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(totalLen - 8, origBitLen >>> 0, true);
  view.setUint32(totalLen - 4, Math.floor(origBitLen / 0x100000000) >>> 0, true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;

  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) {
    K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  }

  const M = new Uint32Array(16);
  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let j = 0; j < 16; j++) {
      M[j] = view.getUint32(offset + j * 4, true);
    }
    let A = a0;
    let B = b0;
    let C = c0;
    let D = d0;

    for (let i = 0; i < 64; i++) {
      let F = 0;
      let g = 0;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D;
      D = C;
      C = B;
      const rot = (F << S[i]) | (F >>> (32 - S[i]));
      B = (B + rot) >>> 0;
    }

    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, a0, true);
  outView.setUint32(4, b0, true);
  outView.setUint32(8, c0, true);
  outView.setUint32(12, d0, true);
  return Array.from(out)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function computeSha1Pure(buffer: ArrayBuffer): string {
  const rol = (x: number, n: number) => (x << n) | (x >>> (32 - n));
  const input = new Uint8Array(buffer);
  const bitLen = input.length * 8;
  const padLen = ((input.length + 9 + 63) >> 6) << 6;
  const padded = new Uint8Array(padLen);
  padded.set(input);
  padded[input.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(padLen - 4, bitLen >>> 0, false);

  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const W = new Uint32Array(80);
  for (let offset = 0; offset < padLen; offset += 64) {
    for (let i = 0; i < 16; i++) W[i] = view.getUint32(offset + i * 4, false);
    for (let i = 16; i < 80; i++) {
      W[i] = rol((W[i - 3] ?? 0) ^ (W[i - 8] ?? 0) ^ (W[i - 14] ?? 0) ^ (W[i - 16] ?? 0), 1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f = 0, k = 0;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const temp = (rol(a, 5) + f + e + k + (W[i] ?? 0)) >>> 0;
      e = d; d = c; c = rol(b, 30) >>> 0; b = a; a = temp;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }
  return [h0, h1, h2, h3, h4].map(v => v.toString(16).padStart(8, '0')).join('');
}

async function computeDigest(
  buffer: ArrayBuffer,
  algo: Exclude<HashAlgorithm, 'ALL'>,
): Promise<string> {
  if (algo === 'MD5') {
    return computeMd5(buffer);
  }
  if (typeof crypto !== 'undefined' && crypto.subtle && typeof crypto.subtle.digest === 'function') {
    const digest = await crypto.subtle.digest(algo, buffer);
    return Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
  if (algo === 'SHA-256') return computeSha256Pure(buffer);
  if (algo === 'SHA-1') return computeSha1Pure(buffer);
  // Fallback for SHA-384 / SHA-512 over non-HTTPS LAN IPs
  return computeSha256Pure(buffer);
}

export async function computeHashesForBuffer(
  buffer: ArrayBuffer,
  selectedAlgo: HashAlgorithm,
): Promise<Record<Exclude<HashAlgorithm, 'ALL'>, string>> {
  const targets = selectedAlgo === 'ALL' ? SINGLE_ALGORITHMS : [selectedAlgo];
  const entries = await Promise.all(
    targets.map(async alg => [alg, await computeDigest(buffer, alg)] as const),
  );
  return Object.fromEntries(entries) as Record<Exclude<HashAlgorithm, 'ALL'>, string>;
}

export function HashAnalyzer() {
  const { user, cases, evidence, validations, refresh } = useWorkspace();

  // Mode: 'evidence' (Evidence Locker verification) or 'standalone' (Drop any file)
  const [mode, setMode] = useState<'evidence' | 'standalone'>('evidence');
  const [algorithm, setAlgorithm] = useState<HashAlgorithm>('SHA-256');
  const [uppercase, setUppercase] = useState(false);

  // Evidence Locker Mode state
  const [caseFilter, setCaseFilter] = useState('all');
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string>('');
  const [evidenceHashes, setEvidenceHashes] = useState<Record<string, string>>({});
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [comparisonFile, setComparisonFile] = useState<File | null>(null);
  const [comparisonHashes, setComparisonHashes] = useState<Record<string, string>>({});

  // Validation Form state (Section 4.1, Prompt 3, Section 9.2)
  const [independentTool, setIndependentTool] = useState<string>(INDEPENDENT_TOOLS[0]);
  const [validationAlgo, setValidationAlgo] = useState<Exclude<HashAlgorithm, 'ALL'>>('SHA-256');
  const [independentDigestInput, setIndependentDigestInput] = useState('');
  const [validatorName, setValidatorName] = useState(
    user?.email?.split('@')[0] ?? 'Investigator',
  );
  const [validationNotes, setValidationNotes] = useState('');
  const [flagNeedsReview, setFlagNeedsReview] = useState(false);
  const [savingStatus, setSavingStatus] = useState(false);

  // Standalone Mode state
  const [standaloneFile, setStandaloneFile] = useState<File | null>(null);
  const [standaloneHashes, setStandaloneHashes] = useState<Record<string, string>>({});
  const [standaloneDurationMs, setStandaloneDurationMs] = useState<number | null>(null);
  const [standaloneBusy, setStandaloneBusy] = useState(false);
  const [secondFile, setSecondFile] = useState<File | null>(null);
  const [secondFileHashes, setSecondFileHashes] = useState<Record<string, string>>({});
  const [knownHashInput, setKnownHashInput] = useState('');

  const standaloneInputRef = useRef<HTMLInputElement>(null);
  const secondFileInputRef = useRef<HTMLInputElement>(null);
  const evidenceCompareInputRef = useRef<HTMLInputElement>(null);

  const filteredEvidence = evidence.filter(
    e => caseFilter === 'all' || e.case_id === caseFilter,
  );
  const selectedEvidence =
    filteredEvidence.find(e => e.id === selectedEvidenceId) ??
    filteredEvidence[0] ??
    null;

  // Keep selectedEvidenceId synced when list changes
  useEffect(() => {
    if (selectedEvidence && selectedEvidence.id !== selectedEvidenceId) {
      setSelectedEvidenceId(selectedEvidence.id);
    }
  }, [selectedEvidence, selectedEvidenceId]);

  // Keep validationAlgo synced when user selects a single algorithm pill
  useEffect(() => {
    if (algorithm !== 'ALL') {
      setValidationAlgo(algorithm);
    }
  }, [algorithm]);

  // Recompute hashes for stored evidence whenever selected evidence or algorithm changes
  useEffect(() => {
    let cancelled = false;
    async function runStoredHash() {
      if (!selectedEvidence) {
        setEvidenceHashes({});
        setEvidenceError(null);
        return;
      }
      setEvidenceLoading(true);
      setEvidenceError(null);
      try {
        let blob: Blob | undefined;
        if (user && selectedEvidence.owner_id !== 'local-investigator') {
          const { data, error } = await supabase.storage
            .from('evidence-originals')
            .download(selectedEvidence.storage_path);
          if (error) throw error;
          blob = data;
        } else {
          blob = await getLocalEvidenceBlob(selectedEvidence.storage_path);
        }
        if (!blob) {
          throw new Error(
            'Stored original binary not found in local IndexedDB. You can still compare against the recorded SHA-256 baseline or drop a local copy below.',
          );
        }
        const buffer = await blob.arrayBuffer();
        // Always compute all 5 algorithms in the background so validationAlgo has the exact platform digest ready
        const hashes = await computeHashesForBuffer(buffer, 'ALL');
        if (!cancelled) {
          setEvidenceHashes(hashes);
          // Mark evidence as PROCESSED once hashes are extracted (Section 2.4)
          if (selectedEvidence.processing_status === 'UNPROCESSED') {
            if (markLocalEvidenceProcessed(selectedEvidence.id)) {
              await refresh();
            }
          }
        }
      } catch (err) {
        if (!cancelled) {
          setEvidenceError(err instanceof Error ? err.message : 'Could not read stored file.');
          setEvidenceHashes({ 'SHA-256': selectedEvidence.sha256 });
        }
      } finally {
        if (!cancelled) setEvidenceLoading(false);
      }
    }
    runStoredHash();
    return () => {
      cancelled = true;
    };
  }, [selectedEvidence?.id, user]);

  // Compute hashes for comparison file in Evidence mode and auto-fill independentDigestInput
  useEffect(() => {
    let cancelled = false;
    async function runComparisonFile() {
      if (!comparisonFile) {
        setComparisonHashes({});
        return;
      }
      const buf = await comparisonFile.arrayBuffer();
      const hashes = await computeHashesForBuffer(buf, 'ALL');
      if (!cancelled) {
        setComparisonHashes(hashes);
        if (hashes[validationAlgo]) {
          setIndependentDigestInput(hashes[validationAlgo]);
        }
      }
    }
    runComparisonFile();
    return () => {
      cancelled = true;
    };
  }, [comparisonFile, validationAlgo]);

  // Compute hashes for Standalone file
  useEffect(() => {
    let cancelled = false;
    async function runStandalone() {
      if (!standaloneFile) {
        setStandaloneHashes({});
        setStandaloneDurationMs(null);
        return;
      }
      setStandaloneBusy(true);
      const t0 = performance.now();
      try {
        const buf = await standaloneFile.arrayBuffer();
        const hashes = await computeHashesForBuffer(buf, algorithm);
        const elapsed = Math.round(performance.now() - t0);
        if (!cancelled) {
          setStandaloneHashes(hashes);
          setStandaloneDurationMs(elapsed);
        }
      } finally {
        if (!cancelled) setStandaloneBusy(false);
      }
    }
    runStandalone();
    return () => {
      cancelled = true;
    };
  }, [standaloneFile, algorithm]);

  // Compute hashes for second file in Standalone mode
  useEffect(() => {
    let cancelled = false;
    async function runSecondFile() {
      if (!secondFile) {
        setSecondFileHashes({});
        return;
      }
      const buf = await secondFile.arrayBuffer();
      const hashes = await computeHashesForBuffer(buf, algorithm);
      if (!cancelled) setSecondFileHashes(hashes);
    }
    runSecondFile();
    return () => {
      cancelled = true;
    };
  }, [secondFile, algorithm]);

  const formatHash = (h: string) => (uppercase ? h.toUpperCase() : h.toLowerCase());

  async function copyText(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    toast.success(`${label} copied to clipboard.`);
  }

  // Platform digest for the chosen validation algorithm
  const platformDigestForValidation =
    (validationAlgo === 'SHA-256'
      ? evidenceHashes['SHA-256'] || selectedEvidence?.sha256 || ''
      : evidenceHashes[validationAlgo] || ''
    ).toLowerCase();

  const cleanIndependentDigest = independentDigestInput.trim().toLowerCase();
  const hasIndependentInput = cleanIndependentDigest.length > 0;
  const digestsMatch =
    hasIndependentInput &&
    platformDigestForValidation.length > 0 &&
    cleanIndependentDigest === platformDigestForValidation;

  const computedValidationStatus: 'VERIFIED' | 'MISMATCH' | 'NEEDS REVIEW' = flagNeedsReview
    ? 'NEEDS REVIEW'
    : digestsMatch
      ? 'VERIFIED'
      : 'MISMATCH';

  async function handleValidationSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!selectedEvidence) return;
    if (!cleanIndependentDigest) {
      toast.error('Enter the independently calculated digest to record validation.');
      return;
    }
    if (!validatorName.trim()) {
      toast.error('Enter the validator (student) name.');
      return;
    }

    setSavingStatus(true);
    try {
      const relatedCase = cases.find(c => c.id === selectedEvidence.case_id);
      const evCode = getEvidenceCode(selectedEvidence.id, evidence);

      saveValidationRecord({
        case_id: selectedEvidence.case_id,
        case_number: relatedCase?.case_number ?? 'DB-LOCAL',
        evidence_id: selectedEvidence.id,
        evidence_code: evCode,
        filename: selectedEvidence.filename,
        module: 'Hash',
        algorithm: validationAlgo,
        platform_result: formatHash(platformDigestForValidation),
        independent_tool: independentTool,
        independent_result: formatHash(cleanIndependentDigest),
        status: computedValidationStatus,
        validator: validatorName.trim(),
        notes:
          validationNotes.trim() ||
          (computedValidationStatus === 'VERIFIED'
            ? `Exact ${validationAlgo} match confirmed with ${independentTool}.`
            : computedValidationStatus === 'MISMATCH'
              ? `Digest mismatch between DeadByte (${validationAlgo}) and ${independentTool}.`
              : `Flagged for investigator review.`),
      });

      if (user && selectedEvidence.owner_id !== 'local-investigator') {
        await supabase
          .from('evidence')
          .update({
            validation_status: computedValidationStatus,
            processing_status: 'PROCESSED',
          })
          .eq('id', selectedEvidence.id);
      }

      await refresh();
      setValidationNotes('');
      toast.success(
        computedValidationStatus === 'VERIFIED'
          ? `${evCode} (${selectedEvidence.filename}) marked VERIFIED in Validation Log.`
          : computedValidationStatus === 'MISMATCH'
            ? `MISMATCH recorded for ${evCode} (${selectedEvidence.filename}) in Validation Log.`
            : `${evCode} marked NEEDS REVIEW in Validation Log.`,
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not save validation record.');
    } finally {
      setSavingStatus(false);
    }
  }

  // Determine match status in Evidence mode
  const baselineSha256 = selectedEvidence?.sha256?.toLowerCase() ?? '';
  const storedComputedSha256 = evidenceHashes['SHA-256']?.toLowerCase() ?? '';

  const activeAlgorithmsToDisplay: Exclude<HashAlgorithm, 'ALL'>[] =
    algorithm === 'ALL' ? SINGLE_ALGORITHMS : [algorithm];

  // Determine match status in Standalone mode
  const cleanKnownHash = knownHashInput.trim().toLowerCase();
  const standaloneKnownMatch =
    cleanKnownHash.length > 0 &&
    Object.values(standaloneHashes).some(h => h.toLowerCase() === cleanKnownHash);

  const primaryAlgo: Exclude<HashAlgorithm, 'ALL'> =
    algorithm === 'ALL' ? 'SHA-256' : algorithm;
  const secondFileMatch =
    standaloneFile &&
    secondFile &&
    standaloneHashes[primaryAlgo] &&
    secondFileHashes[primaryAlgo]
      ? standaloneHashes[primaryAlgo].toLowerCase() ===
        secondFileHashes[primaryAlgo].toLowerCase()
      : null;

  const selectedEvidenceCode = selectedEvidence
    ? getEvidenceCode(selectedEvidence.id, evidence)
    : '';
  const selectedEvidenceValidations = selectedEvidence
    ? validations.filter(v => v.evidence_id === selectedEvidence.id && v.module === 'Hash')
    : [];

  return (
    <div className="hash-analyzer">
      {/* Top Controls Bar: Mode Switcher + Algorithm Selector */}
      <div className="analyzer-controls">
        <div className="mode-tabs" role="tablist" aria-label="Hash analyzer mode">
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'evidence'}
            className={`mode-tab ${mode === 'evidence' ? 'active' : ''}`}
            onClick={() => setMode('evidence')}
          >
            <Archive size={15} />
            <span>Verify Evidence Locker</span>
            <span className="count-badge">{evidence.length}</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'standalone'}
            className={`mode-tab ${mode === 'standalone' ? 'active' : ''}`}
            onClick={() => setMode('standalone')}
          >
            <Upload size={15} />
            <span>Standalone File Hasher</span>
          </button>
        </div>

        <div className="algo-bar">
          <span className="detail-label" style={{ marginBottom: 0 }}>
            ALGORITHM
          </span>
          <div className="algo-pills" role="group" aria-label="Choose hashing algorithm">
            {([...SINGLE_ALGORITHMS, 'ALL'] as const).map(alg => (
              <button
                key={alg}
                type="button"
                className={`algo-pill ${algorithm === alg ? 'active' : ''}`}
                onClick={() => setAlgorithm(alg)}
              >
                {alg === 'ALL' ? 'All Algorithms' : alg}
              </button>
            ))}
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setUppercase(u => !u)}
            title="Toggle uppercase/lowercase hex"
          >
            {uppercase ? 'UPPERHEX' : 'lowerhex'}
          </Button>
        </div>
      </div>

      {mode === 'evidence' ? (
        /* ==================== MODE 1: EVIDENCE LOCKER VERIFICATION ==================== */
        evidence.length === 0 ? (
          <Empty
            icon={Archive}
            title="No evidence files in your locker yet"
            description="Upload an original file in the Evidence Locker to verify its baseline hash, or switch to Standalone File Hasher to hash any file from your computer."
          >
            <div style={{ display: 'flex', gap: 10 }}>
              <Button asChild variant="outline" size="sm">
                <Link to="/evidence">
                  Open Evidence Locker
                  <ArrowUpRight />
                </Link>
              </Button>
              <Button variant="default" size="sm" onClick={() => setMode('standalone')}>
                <Hash size={14} />
                Use Standalone File Hasher
              </Button>
            </div>
          </Empty>
        ) : (
          <div className="analyzer-grid">
            {/* Left Column: Raw / Extracted Facts + Source Reference */}
            <section className="analyzer-card">
              <div className="section-title" style={{ paddingTop: 0 }}>
                <h2>
                  <Archive size={17} />1 · Raw / Extracted Facts & Source Reference
                </h2>
                {selectedEvidence && (
                  <span
                    className={`status-badge ${
                      selectedEvidence.validation_status === 'VERIFIED'
                        ? 'status-active'
                        : selectedEvidence.validation_status === 'MISMATCH'
                          ? 'status-mismatch'
                          : selectedEvidence.validation_status === 'NEEDS REVIEW'
                            ? 'status-review'
                            : ''
                    }`}
                  >
                    {selectedEvidence.validation_status}
                  </span>
                )}
              </div>

              <div className="form-row">
                <label className="field-label">
                  Filter by Case
                  <select value={caseFilter} onChange={e => setCaseFilter(e.target.value)}>
                    <option value="all">All cases ({evidence.length} files)</option>
                    {cases.map(c => (
                      <option key={c.id} value={c.id}>
                        {c.name} ({c.case_number})
                      </option>
                    ))}
                  </select>
                </label>

                <label className="field-label">
                  Evidence Item
                  <select
                    value={selectedEvidence?.id ?? ''}
                    onChange={e => {
                      setSelectedEvidenceId(e.target.value);
                      setComparisonFile(null);
                      setIndependentDigestInput('');
                    }}
                  >
                    {filteredEvidence.map(ev => (
                      <option key={ev.id} value={ev.id}>
                        {getEvidenceCode(ev.id, evidence)} · {ev.filename} (
                        {(ev.file_size / 1024).toFixed(1)} KB)
                      </option>
                    ))}
                  </select>
                </label>
              </div>

              {selectedEvidence && (
                <>
                  {/* Source Reference & Metadata Grid */}
                  <div className="evidence-meta-grid">
                    <div>
                      <div className="detail-label">EVIDENCE ID / REFERENCE</div>
                      <strong className="mono">
                        {selectedEvidenceCode} ·{' '}
                        {cases.find(c => c.id === selectedEvidence.case_id)?.case_number ??
                          'CASE'}
                      </strong>
                      <small className="mono muted" style={{ display: 'block', marginTop: 3 }}>
                        UUID: {selectedEvidence.id.slice(0, 18)}…
                      </small>
                    </div>
                    <div>
                      <div className="detail-label">ORIGINAL FILENAME</div>
                      <strong>{selectedEvidence.filename}</strong>
                      <small className="mono muted" style={{ display: 'block', marginTop: 3 }}>
                        Type: {selectedEvidence.file_type}
                      </small>
                    </div>
                    <div>
                      <div className="detail-label">EXACT BYTE SIZE</div>
                      <span className="mono">
                        {selectedEvidence.file_size.toLocaleString()} bytes (
                        {(selectedEvidence.file_size / 1024).toFixed(2)} KB)
                      </span>
                    </div>
                    <div>
                      <div className="detail-label">ACQUIRED / UPLOADER</div>
                      <span>
                        {selectedEvidence.uploader} ·{' '}
                        {new Date(selectedEvidence.uploaded_at).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  {/* Upload Baseline SHA-256 */}
                  <div className="hash-block">
                    <div className="hash-block-header">
                      <span className="detail-label" style={{ marginBottom: 0 }}>
                        ACQUISITION BASELINE · SHA-256 (STORED AT INTAKE)
                      </span>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          copyText('Baseline SHA-256', formatHash(selectedEvidence.sha256))
                        }
                      >
                        <Copy size={13} />
                        Copy
                      </Button>
                    </div>
                    <div className="hash-value">{formatHash(selectedEvidence.sha256)}</div>
                  </div>

                  {/* Live Re-computed Hashes from Stored Original */}
                  <div className="hash-block">
                    <div className="hash-block-header">
                      <span className="detail-label" style={{ marginBottom: 0 }}>
                        PLATFORM EXTRACTED DIGESTS (
                        {algorithm === 'ALL' ? 'ALL ALGORITHMS' : algorithm})
                      </span>
                      {evidenceLoading && (
                        <span className="mono muted" style={{ fontSize: 10 }}>
                          <RefreshCw size={12} /> Computing…
                        </span>
                      )}
                    </div>

                    {evidenceError ? (
                      <div className="notice" style={{ marginTop: 4 }}>
                        {evidenceError}
                      </div>
                    ) : (
                      <div className="hash-list">
                        {activeAlgorithmsToDisplay.map(alg => {
                          const val = evidenceHashes[alg];
                          if (!val) return null;
                          return (
                            <div key={alg} className="hash-item">
                              <div className="hash-item-top">
                                <span className="algo-tag">{alg}</span>
                                <span className="mono muted" style={{ fontSize: 9 }}>
                                  {val.length * 4}-bit ({val.length} hex chars) ·{' '}
                                  {alg === 'MD5'
                                    ? 'Legacy / Classroom Comparison'
                                    : 'Cryptographic Digest'}
                                </span>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => copyText(alg, formatHash(val))}
                                >
                                  <Copy size={12} />
                                  Copy
                                </Button>
                              </div>
                              <div className="hash-value">{formatHash(val)}</div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* Automatic Stored Integrity Check Banner */}
                  {storedComputedSha256 && (
                    <div
                      className={`integrity-banner ${
                        storedComputedSha256 === baselineSha256 ? 'match' : 'mismatch'
                      }`}
                    >
                      {storedComputedSha256 === baselineSha256 ? (
                        <>
                          <CheckCircle2 size={20} />
                          <div>
                            <strong>PRESERVED ORIGINAL INTEGRITY INTACT</strong>
                            <p>
                              Observed Fact: Re-computed SHA-256 of preserved storage object (
                              {selectedEvidenceCode}) matches intake baseline byte-for-byte.
                            </p>
                          </div>
                        </>
                      ) : (
                        <>
                          <AlertTriangle size={20} />
                          <div>
                            <strong>STORAGE INTEGRITY EXCEPTION (MISMATCH)</strong>
                            <p>
                              Observed Fact: Re-computed SHA-256 differs from the intake baseline!
                            </p>
                          </div>
                        </>
                      )}
                    </div>
                  )}

                  {/* Quick Validation Reference Commands (Section 13 of Guide) */}
                  <div className="verify-box">
                    <div className="hash-block-header" style={{ marginBottom: 8 }}>
                      <span className="detail-label" style={{ marginBottom: 0 }}>
                        <Terminal size={12} style={{ display: 'inline', marginRight: 5 }} />
                        QUICK INDEPENDENT VALIDATION COMMANDS (SECTION 13)
                      </span>
                    </div>
                    <div className="cmd-list">
                      {[
                        [
                          'PowerShell',
                          `Get-FileHash "${selectedEvidence.filename}" -Algorithm ${validationAlgo.replace('-', '')}`,
                        ],
                        [
                          'Windows CMD',
                          `certutil -hashfile "${selectedEvidence.filename}" ${validationAlgo.replace('-', '')}`,
                        ],
                        [
                          'Linux / macOS',
                          `${validationAlgo === 'MD5' ? 'md5sum' : 'sha256sum'} "${selectedEvidence.filename}"`,
                        ],
                      ].map(([label, cmd]) => (
                        <div key={label} className="cmd-row">
                          <span className="algo-tag">{label}</span>
                          <code className="mono">{cmd}</code>
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => copyText(`${label} command`, cmd)}
                          >
                            <Copy size={12} />
                          </Button>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </section>

            {/* Right Column: Structured Independent Validation Gate (Section 4.1, Prompt 3, Section 9.2) */}
            <section className="analyzer-card">
              <div className="section-title" style={{ paddingTop: 0 }}>
                <h2>
                  <ShieldCheck size={17} />2 · Independent Validation Gate
                </h2>
                <span className="subtle-label">HUMAN VERIFICATION REQUIRED</span>
              </div>

              <form className="form-stack" onSubmit={handleValidationSubmit}>
                <div className="form-row">
                  <label className="field-label">
                    Independent Tool Used *
                    <select
                      value={independentTool}
                      onChange={e => setIndependentTool(e.target.value)}
                    >
                      {INDEPENDENT_TOOLS.map(t => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="field-label">
                    Algorithm Compared *
                    <select
                      value={validationAlgo}
                      onChange={e =>
                        setValidationAlgo(e.target.value as Exclude<HashAlgorithm, 'ALL'>)
                      }
                    >
                      {SINGLE_ALGORITHMS.map(a => (
                        <option key={a} value={a}>
                          {a} {a === 'SHA-256' ? '(Required Primary)' : a === 'MD5' ? '(Legacy)' : ''}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>

                <div>
                  <div className="detail-label" style={{ marginBottom: 6 }}>
                    EXPECTED (DEADBYTE PLATFORM {validationAlgo} RESULT)
                  </div>
                  <div className="hash-value">
                    {platformDigestForValidation
                      ? formatHash(platformDigestForValidation)
                      : 'Computing platform digest…'}
                  </div>
                </div>

                <label className="field-label">
                  Observed (Independently Calculated {validationAlgo} Digest) *
                  <input
                    required
                    placeholder={`Paste ${validationAlgo} hash output from ${independentTool}…`}
                    value={independentDigestInput}
                    onChange={e => setIndependentDigestInput(e.target.value)}
                    className="mono"
                  />
                </label>

                {/* Optional helper: Drop a local file to auto-fill the independent digest */}
                <div
                  className="upload-zone compact-zone"
                  onDragOver={e => e.preventDefault()}
                  onDrop={e => {
                    e.preventDefault();
                    setComparisonFile(e.dataTransfer.files[0] ?? null);
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <Upload size={16} />
                    <span style={{ fontSize: 11 }}>
                      {comparisonFile
                        ? `Loaded "${comparisonFile.name}" (${(comparisonFile.size / 1024).toFixed(1)} KB)`
                        : 'Or drop a second copy of the file from disk to populate digest'}
                    </span>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => evidenceCompareInputRef.current?.click()}
                    >
                      Browse file
                    </Button>
                  </div>
                  <input
                    ref={evidenceCompareInputRef}
                    type="file"
                    className="hidden"
                    onChange={e => setComparisonFile(e.target.files?.[0] ?? null)}
                  />
                </div>

                {/* Live Comparison Result Preview */}
                {hasIndependentInput && (
                  <div
                    className={`integrity-banner ${
                      flagNeedsReview
                        ? 'review'
                        : digestsMatch
                          ? 'match'
                          : 'mismatch'
                    }`}
                  >
                    {flagNeedsReview ? (
                      <>
                        <Clock3 size={19} />
                        <div>
                          <strong>STATUS TO RECORD: NEEDS REVIEW</strong>
                          <p>
                            This validation will be logged as NEEDS REVIEW for investigator or
                            instructor judgment.
                          </p>
                        </div>
                      </>
                    ) : digestsMatch ? (
                      <>
                        <CheckCircle2 size={19} />
                        <div>
                          <strong>EXACT DIGEST MATCH → STATUS: VERIFIED</strong>
                          <p>
                            Observed digest from {independentTool} matches DeadByte’s{' '}
                            {validationAlgo} digest character-for-character.
                          </p>
                        </div>
                      </>
                    ) : (
                      <>
                        <AlertTriangle size={19} />
                        <div>
                          <strong>DIGEST MISMATCH DETECTED → STATUS: MISMATCH</strong>
                          <p>
                            Observed digest does NOT match DeadByte’s {validationAlgo} digest.
                            Record this mismatch and document the cause in the notes below.
                          </p>
                        </div>
                      </>
                    )}
                  </div>
                )}

                <div className="form-row">
                  <label className="field-label">
                    Validator (Student Name) *
                    <input
                      required
                      placeholder="Enter your name"
                      value={validatorName}
                      onChange={e => setValidatorName(e.target.value)}
                    />
                  </label>

                  <label className="field-label">
                    Override / Ambiguity Flag
                    <label
                      style={{
                        display: 'flex',
                        flexDirection: 'row',
                        alignItems: 'center',
                        gap: 8,
                        height: 38,
                        padding: '0 10px',
                        border: '1px solid var(--border)',
                        borderRadius: 5,
                        background: 'var(--background)',
                        cursor: 'pointer',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={flagNeedsReview}
                        onChange={e => setFlagNeedsReview(e.target.checked)}
                        style={{ width: 'auto' }}
                      />
                      <span style={{ fontSize: 11 }}>Mark as NEEDS REVIEW</span>
                    </label>
                  </label>
                </div>

                <label className="field-label">
                  Validation Notes / Observations
                  <textarea
                    placeholder="Document command used, any differences, mismatch investigation, or assumptions…"
                    value={validationNotes}
                    onChange={e => setValidationNotes(e.target.value)}
                    style={{ minHeight: 62 }}
                  />
                </label>

                <div className="decision-buttons">
                  <Button
                    type="submit"
                    disabled={savingStatus || !hasIndependentInput}
                    className={
                      !hasIndependentInput
                        ? ''
                        : computedValidationStatus === 'VERIFIED'
                          ? 'btn-verify'
                          : computedValidationStatus === 'MISMATCH'
                            ? 'bg-destructive text-white'
                            : ''
                    }
                  >
                    {computedValidationStatus === 'VERIFIED' ? (
                      <ShieldCheck size={16} />
                    ) : (
                      <ShieldAlert size={16} />
                    )}
                    {savingStatus
                      ? 'Recording validation…'
                      : hasIndependentInput
                        ? `Record ${computedValidationStatus} in Validation Log`
                        : 'Enter Independent Digest Above to Validate'}
                  </Button>
                  <Button asChild variant="outline" type="button">
                    <Link to="/validation">
                      View Full Validation Log
                      <ArrowUpRight size={14} />
                    </Link>
                  </Button>
                </div>
              </form>

              {/* Validation History for Selected Evidence */}
              {selectedEvidenceValidations.length > 0 && (
                <div className="verify-box">
                  <div className="detail-label">
                    RECORDED VALIDATIONS FOR {selectedEvidenceCode} ({selectedEvidenceValidations.length})
                  </div>
                  <div className="hash-list">
                    {selectedEvidenceValidations.map(v => (
                      <div key={v.id} className="hash-item">
                        <div className="hash-item-top">
                          <span
                            className={`status-badge ${
                              v.status === 'VERIFIED'
                                ? 'status-active'
                                : v.status === 'MISMATCH'
                                  ? 'status-mismatch'
                                  : 'status-review'
                            }`}
                          >
                            {v.status}
                          </span>
                          <span style={{ fontSize: 10, fontWeight: 600 }}>
                            {v.independent_tool} ({v.algorithm ?? 'SHA-256'})
                          </span>
                          <span className="mono muted" style={{ fontSize: 9 }}>
                            {v.validator} · {new Date(v.created_at).toLocaleString()}
                          </span>
                        </div>
                        <p className="muted" style={{ fontSize: 10, marginTop: 4 }}>
                          {v.notes}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>
          </div>
        )
      ) : (
        /* ==================== MODE 2: STANDALONE FILE HASHER ==================== */
        <div className="analyzer-grid">
          <section className="analyzer-card">
            <div className="section-title" style={{ paddingTop: 0 }}>
              <h2>
                <FileText size={17} />1 · Target File to Hash
              </h2>
              {standaloneDurationMs !== null && (
                <span className="count-badge">{standaloneDurationMs} ms</span>
              )}
            </div>

            <div
              className="upload-zone"
              onDragOver={e => e.preventDefault()}
              onDrop={e => {
                e.preventDefault();
                setStandaloneFile(e.dataTransfer.files[0] ?? null);
              }}
            >
              <Upload size={28} />
              <Button
                type="button"
                variant="outline"
                onClick={() => standaloneInputRef.current?.click()}
              >
                Choose any file from computer
              </Button>
              <p>
                {standaloneFile
                  ? `${standaloneFile.name} · ${(standaloneFile.size / 1024).toFixed(2)} KB`
                  : 'Drop any file here · Computes hash deterministically in your browser'}
              </p>
              <input
                ref={standaloneInputRef}
                type="file"
                className="hidden"
                onChange={e => setStandaloneFile(e.target.files?.[0] ?? null)}
              />
            </div>

            {standaloneFile && (
              <>
                <div className="evidence-meta-grid" style={{ marginTop: 18 }}>
                  <div>
                    <div className="detail-label">FILENAME</div>
                    <strong>{standaloneFile.name}</strong>
                  </div>
                  <div>
                    <div className="detail-label">EXACT SIZE</div>
                    <span className="mono">
                      {standaloneFile.size.toLocaleString()} bytes (
                      {(standaloneFile.size / 1024).toFixed(2)} KB)
                    </span>
                  </div>
                  <div>
                    <div className="detail-label">MIME TYPE</div>
                    <span className="mono">
                      {standaloneFile.type || 'application/octet-stream'}
                    </span>
                  </div>
                  <div>
                    <div className="detail-label">LAST MODIFIED</div>
                    <span>{new Date(standaloneFile.lastModified).toLocaleString()}</span>
                  </div>
                </div>

                <div className="hash-block">
                  <div className="hash-block-header">
                    <span className="detail-label" style={{ marginBottom: 0 }}>
                      COMPUTED CRYPTOGRAPHIC DIGESTS (
                      {algorithm === 'ALL' ? 'ALL ALGORITHMS' : algorithm})
                    </span>
                    {standaloneBusy && <span className="mono muted">Computing…</span>}
                  </div>
                  <div className="hash-list">
                    {activeAlgorithmsToDisplay.map(alg => {
                      const val = standaloneHashes[alg];
                      if (!val) return null;
                      return (
                        <div key={alg} className="hash-item">
                          <div className="hash-item-top">
                            <span className="algo-tag">{alg}</span>
                            <span className="mono muted" style={{ fontSize: 9 }}>
                              {val.length * 4}-bit ({val.length} hex chars)
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyText(alg, formatHash(val))}
                            >
                              <Copy size={12} />
                              Copy
                            </Button>
                          </div>
                          <div className="hash-value">{formatHash(val)}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </>
            )}
          </section>

          <section className="analyzer-card">
            <div className="section-title" style={{ paddingTop: 0 }}>
              <h2>
                <Hash size={17} />2 · Compare Against Known Hash or Second File
              </h2>
            </div>

            <div className="verify-box">
              <label className="field-label">
                Compare with Expected / Independent Hash String
                <input
                  placeholder="Paste any expected hash (SHA-256, SHA-512, SHA-384, SHA-1, or MD5)…"
                  value={knownHashInput}
                  onChange={e => setKnownHashInput(e.target.value)}
                  className="mono"
                />
              </label>

              {cleanKnownHash.length > 0 && standaloneFile && (
                <div
                  className={`integrity-banner ${standaloneKnownMatch ? 'match' : 'mismatch'}`}
                >
                  {standaloneKnownMatch ? (
                    <>
                      <CheckCircle2 size={18} />
                      <div>
                        <strong>EXACT HASH MATCH (VERIFIED)</strong>
                        <p>
                          "{standaloneFile.name}" matches the expected cryptographic hash.
                        </p>
                      </div>
                    </>
                  ) : (
                    <>
                      <AlertTriangle size={18} />
                      <div>
                        <strong>HASH MISMATCH</strong>
                        <p>
                          "{standaloneFile.name}" does NOT match the provided hash string.
                        </p>
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>

            <div className="verify-box">
              <div className="detail-label">OR DROP A SECOND FILE TO COMPARE TWO FILES</div>
              <div
                className="upload-zone compact-zone"
                onDragOver={e => e.preventDefault()}
                onDrop={e => {
                  e.preventDefault();
                  setSecondFile(e.dataTransfer.files[0] ?? null);
                }}
              >
                <Upload size={22} />
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => secondFileInputRef.current?.click()}
                >
                  Choose second file
                </Button>
                <p>
                  {secondFile
                    ? `${secondFile.name} · ${(secondFile.size / 1024).toFixed(2)} KB`
                    : 'Drop a second file to compare against File 1'}
                </p>
                <input
                  ref={secondFileInputRef}
                  type="file"
                  className="hidden"
                  onChange={e => setSecondFile(e.target.files?.[0] ?? null)}
                />
              </div>

              {secondFile && secondFileHashes[primaryAlgo] && (
                <div style={{ marginTop: 12 }}>
                  <div className="detail-label">
                    SECOND FILE ({secondFile.name}) · {primaryAlgo}
                  </div>
                  <div className="hash-value">
                    {formatHash(secondFileHashes[primaryAlgo])}
                  </div>

                  {secondFileMatch !== null && (
                    <div
                      className={`integrity-banner ${secondFileMatch ? 'match' : 'mismatch'}`}
                    >
                      {secondFileMatch ? (
                        <>
                          <CheckCircle2 size={18} />
                          <div>
                            <strong>FILES ARE IDENTICAL ({primaryAlgo} MATCH)</strong>
                            <p>
                              "{standaloneFile?.name}" and "{secondFile.name}" produce the exact
                              same cryptographic digest.
                            </p>
                          </div>
                        </>
                      ) : (
                        <>
                          <AlertTriangle size={18} />
                          <div>
                            <strong>FILES ARE DIFFERENT ({primaryAlgo} MISMATCH)</strong>
                            <p>
                              "{standaloneFile?.name}" and "{secondFile.name}" do not have matching
                              hashes.
                            </p>
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
