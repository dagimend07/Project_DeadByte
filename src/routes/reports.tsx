import { createFileRoute, Link } from '@tanstack/react-router';
import { useState, useMemo } from 'react';
import {
  useWorkspace,
  PageHeading,
  Empty,
  getEvidenceCode,
} from '@/components/deadbyte/workspace';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import {
  FileText,
  Download,
  Printer,
  ShieldCheck,
  ShieldAlert,
  Clock3,
  FolderKanban,
  Archive,
  CheckCircle2,
  AlertTriangle,
  ArrowUpRight,
  Copy,
} from 'lucide-react';

export const Route = createFileRoute('/reports')({
  head: () => ({
    meta: [
      { title: 'Investigation Reports — DeadByte' },
      {
        name: 'description',
        content: 'Court-style digital forensics investigation reports with verified evidence and chain of custody.',
      },
      { property: 'og:title', content: 'Investigation Reports — DeadByte' },
      {
        property: 'og:description',
        content: 'Investigator-approved evidence inventories, verified findings, and 9-column validation logs.',
      },
      { property: 'og:type', content: 'website' },
      { name: 'twitter:card', content: 'summary_large_image' },
    ],
  }),
  component: ForensicReportsPage,
});

function ForensicReportsPage() {
  const { cases, evidence, activity, validations } = useWorkspace();
  const [selectedCaseId, setSelectedCaseId] = useState<string>('ALL');
  const [examinerName, setExaminerName] = useState<string>('');
  const [agencyName, setAgencyName] = useState<string>('');
  const [executiveSummary, setExecutiveSummary] = useState<string>('');
  const [conclusionsText, setConclusionsText] = useState<string>('');

  const selectedCase = useMemo(
    () => (selectedCaseId === 'ALL' ? null : cases.find((c) => c.id === selectedCaseId) ?? null),
    [cases, selectedCaseId]
  );

  const effectiveExaminer =
    examinerName.trim() || selectedCase?.investigator || cases[0]?.investigator || 'Not Specified';
  const effectiveAgency = agencyName.trim() || 'Not Specified';
  const effectiveSummary =
    executiveSummary.trim() ||
    (selectedCase?.description
      ? selectedCase.description
      : 'No executive summary entered by investigator.');
  const effectiveConclusions =
    conclusionsText.trim() ||
    (selectedCase?.notes
      ? selectedCase.notes
      : 'No forensic conclusions entered by investigator.');

  const reportCases = useMemo(
    () => (selectedCase ? [selectedCase] : cases),
    [cases, selectedCase]
  );

  const reportEvidence = useMemo(
    () =>
      evidence.filter((e) =>
        selectedCaseId === 'ALL' ? true : e.case_id === selectedCaseId
      ),
    [evidence, selectedCaseId]
  );

  const reportValidations = useMemo(
    () =>
      validations.filter((v) =>
        selectedCaseId === 'ALL' ? true : v.case_id === selectedCaseId
      ),
    [validations, selectedCaseId]
  );

  const reportActivity = useMemo(
    () =>
      activity.filter((a) =>
        selectedCaseId === 'ALL' ? true : a.case_id === selectedCaseId
      ),
    [activity, selectedCaseId]
  );

  const verifiedEvidenceCount = reportEvidence.filter((e) => e.validation_status === 'VERIFIED').length;
  const mismatchEvidenceCount = reportEvidence.filter((e) => e.validation_status === 'MISMATCH').length;
  const unverifiedEvidenceCount = reportEvidence.filter(
    (e) => e.validation_status !== 'VERIFIED' && e.validation_status !== 'MISMATCH'
  ).length;

  const reportDateUtc = new Date().toISOString();
  const reportTitle = selectedCase
    ? `Forensic Investigation Report — ${selectedCase.name} (${selectedCase.case_number})`
    : `Master Forensic Investigation Report — All Cases (${cases.length})`;

  function buildMarkdownReport(): string {
    const lines: string[] = [];
    lines.push(`# ${reportTitle}`);
    lines.push(`**Generated (UTC):** ${reportDateUtc}`);
    lines.push(`**Lead Forensic Examiner:** ${effectiveExaminer}`);
    lines.push(`**Laboratory / Organization:** ${effectiveAgency}`);
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 1. Executive Summary');
    lines.push(effectiveSummary);
    lines.push('');
    lines.push('### Investigation Metrics');
    lines.push(`- **Cases Covered:** ${reportCases.length}`);
    lines.push(`- **Preserved Evidence Files:** ${reportEvidence.length}`);
    lines.push(`- **Independently Verified Items (VERIFIED):** ${verifiedEvidenceCount}`);
    lines.push(`- **Pending / Unverified Items:** ${unverifiedEvidenceCount}`);
    lines.push(`- **Integrity / Validation Mismatches (MISMATCH):** ${mismatchEvidenceCount}`);
    lines.push(`- **Recorded 9-Column Validation Entries:** ${reportValidations.length}`);
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 2. Case Metadata');
    if (reportCases.length === 0) {
      lines.push('_No cases recorded._');
    } else {
      for (const c of reportCases) {
        lines.push(`### ${c.name} (\`${c.case_number}\`)`);
        lines.push(`- **Status:** ${c.status}`);
        lines.push(`- **Investigator:** ${c.investigator || effectiveExaminer}`);
        lines.push(`- **Created (UTC):** ${c.created_at}`);
        lines.push(`- **Description:** ${c.description || 'Not Present'}`);
        lines.push(`- **Investigator Notes:** ${c.notes || 'Not Present'}`);
        lines.push('');
      }
    }
    lines.push('---');
    lines.push('');
    lines.push('## 3. Preserved Evidence Locker Inventory');
    if (reportEvidence.length === 0) {
      lines.push('_No evidence files uploaded._');
    } else {
      lines.push('| Evidence ID | Filename | Size (Bytes) | Intake SHA-256 Digest | Validation Status | Uploaded (UTC) |');
      lines.push('| :--- | :--- | :--- | :--- | :--- | :--- |');
      for (const ev of reportEvidence) {
        const code = getEvidenceCode(ev.id, evidence);
        lines.push(
          `| \`${code}\` | ${ev.filename} | ${ev.file_size.toLocaleString()} | \`${ev.sha256}\` | **${ev.validation_status}** | ${ev.uploaded_at} |`
        );
      }
    }
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 4. 9-Column Independent Validation Log');
    if (reportValidations.length === 0) {
      lines.push('_No independent tool validations recorded yet._');
    } else {
      lines.push(
        '| Evidence ID | Filename | Module | Algorithm / Field | DeadByte Result | Independent Tool | Independent Result | Status | Validator & Timestamp |'
      );
      lines.push('| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |');
      for (const v of reportValidations) {
        lines.push(
          `| \`${v.evidence_code}\` | ${v.filename} | ${v.module} | ${v.algorithm ?? 'Standard'} | \`${v.platform_result}\` | ${v.independent_tool} | \`${v.independent_result}\` | **${v.status}** | ${v.validator} (${v.created_at}) |`
        );
      }
    }
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 5. Chain of Custody & Activity Audit Trail');
    if (reportActivity.length === 0) {
      lines.push('_No activity entries recorded._');
    } else {
      for (const a of reportActivity.slice(0, 40)) {
        lines.push(`- **${a.created_at}** — **${a.action}**: ${a.detail}`);
      }
    }
    lines.push('');
    lines.push('---');
    lines.push('');
    lines.push('## 6. Forensic Conclusions & Verification Attestation');
    lines.push(effectiveConclusions);
    lines.push('');
    return lines.join('\n');
  }

  function downloadMarkdown() {
    const md = buildMarkdownReport();
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const slug = selectedCase ? selectedCase.case_number : 'ALL_CASES';
    a.download = `DeadByte_Forensic_Report_${slug}.md`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast.success('Downloaded Forensic Investigation Report (.md).');
  }

  function downloadHtmlReport() {
    const slug = selectedCase ? selectedCase.case_number : 'ALL_CASES';
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${reportTitle}</title>
  <style>
    body { font-family: 'Segoe UI', Calibri, sans-serif; color: #111827; max-width: 1020px; margin: 32px auto; padding: 0 24px; line-height: 1.55; }
    h1 { color: #4c1d95; border-bottom: 2px solid #6d28d9; padding-bottom: 8px; margin-bottom: 6px; }
    h2 { color: #4c1d95; margin-top: 28px; border-bottom: 1px solid #ddd6fe; padding-bottom: 4px; }
    .meta { background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 14px 18px; margin: 16px 0; font-size: 14px; }
    table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 12.5px; }
    th { background: #4c1d95; color: #ffffff; text-align: left; padding: 8px 10px; }
    td { border-bottom: 1px solid #e2e8f0; padding: 8px 10px; vertical-align: top; word-break: break-word; }
    code { font-family: Consolas, monospace; background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 11.5px; }
    .badge { display: inline-block; padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 11px; }
    .VERIFIED { background: #dcfce7; color: #166534; }
    .MISMATCH { background: #fee2e2; color: #991b1b; }
    .UNVERIFY { background: #fef3c7; color: #92400e; }
  </style>
</head>
<body>
  <h1>${reportTitle}</h1>
  <div class="meta">
    <div><strong>Generated (UTC):</strong> ${reportDateUtc}</div>
    <div><strong>Lead Forensic Examiner:</strong> ${effectiveExaminer}</div>
    <div><strong>Laboratory / Organization:</strong> ${effectiveAgency}</div>
  </div>
  <h2>1. Executive Summary</h2>
  <p>${effectiveSummary}</p>
  <h2>2. Preserved Evidence Locker Inventory (${reportEvidence.length})</h2>
  <table>
    <thead>
      <tr><th>Evidence ID</th><th>Filename</th><th>Size</th><th>Intake SHA-256 Digest</th><th>Status</th><th>Uploaded (UTC)</th></tr>
    </thead>
    <tbody>
      ${
        reportEvidence.length
          ? reportEvidence
              .map((ev) => {
                const code = getEvidenceCode(ev.id, evidence);
                const cls =
                  ev.validation_status === 'VERIFIED'
                    ? 'VERIFIED'
                    : ev.validation_status === 'MISMATCH'
                    ? 'MISMATCH'
                    : 'UNVERIFY';
                return `<tr><td><code>${code}</code></td><td><strong>${ev.filename}</strong></td><td>${ev.file_size.toLocaleString()} B</td><td><code>${ev.sha256}</code></td><td><span class="badge ${cls}">${ev.validation_status}</span></td><td>${ev.uploaded_at}</td></tr>`;
              })
              .join('')
          : '<tr><td colspan="6">No evidence files recorded.</td></tr>'
      }
    </tbody>
  </table>
  <h2>3. 9-Column Independent Validation Log (${reportValidations.length})</h2>
  <table>
    <thead>
      <tr><th>Evidence ID</th><th>File</th><th>Module</th><th>Field/Algo</th><th>DeadByte Result</th><th>External Tool</th><th>External Result</th><th>Status</th><th>Validator</th></tr>
    </thead>
    <tbody>
      ${
        reportValidations.length
          ? reportValidations
              .map((v) => {
                const cls =
                  v.status === 'VERIFIED' ? 'VERIFIED' : v.status === 'MISMATCH' ? 'MISMATCH' : 'UNVERIFY';
                return `<tr><td><code>${v.evidence_code}</code></td><td>${v.filename}</td><td>${v.module}</td><td>${v.algorithm ?? 'Standard'}</td><td><code>${v.platform_result}</code></td><td>${v.independent_tool}</td><td><code>${v.independent_result}</code></td><td><span class="badge ${cls}">${v.status}</span></td><td>${v.validator}<br/><small>${v.created_at}</small></td></tr>`;
              })
              .join('')
          : '<tr><td colspan="9">No independent validations logged yet.</td></tr>'
      }
    </tbody>
  </table>
  <h2>4. Forensic Conclusions & Verification Attestation</h2>
  <p>${effectiveConclusions}</p>
</body>
</html>`;

    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `DeadByte_Forensic_Report_${slug}.html`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast.success('Downloaded standalone HTML Forensic Report.');
  }

  async function copyMarkdown() {
    await navigator.clipboard.writeText(buildMarkdownReport());
    toast.success('Copied full Markdown forensic report to clipboard.');
  }

  const hasAnyWorkspaceData = cases.length > 0 || evidence.length > 0 || validations.length > 0;

  return (
    <div className="page">
      <PageHeading
        eyebrow="MODULE 09 · COURT-STYLE DOCUMENTATION"
        title="Investigation Reports"
        description="Generate court-style forensic investigation reports with chain of custody, SHA-256 evidence inventories, and your 9-Column Independent Validation Log."
      >
        {hasAnyWorkspaceData && (
          <>
            <Button type="button" variant="outline" size="sm" onClick={copyMarkdown}>
              <Copy size={14} /> Copy Markdown
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={downloadMarkdown}>
              <Download size={14} /> Export .MD
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={downloadHtmlReport}>
              <FileText size={14} /> Export .HTML
            </Button>
            <Button type="button" variant="default" size="sm" onClick={() => window.print()}>
              <Printer size={14} /> Print / Save as PDF
            </Button>
          </>
        )}
      </PageHeading>

      {!hasAnyWorkspaceData ? (
        <Empty
          icon={FileText}
          title="No cases or evidence to report on yet"
          description="Create an investigation case and upload evidence in your workspace first. Once you add your own case data, you can generate, customize, and export your forensic report here."
        >
          <div style={{ display: 'flex', gap: 10 }}>
            <Button asChild variant="default" size="sm">
              <Link to="/cases">
                Open Case Manager <ArrowUpRight size={14} />
              </Link>
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link to="/evidence">
                Open Evidence Locker <ArrowUpRight size={14} />
              </Link>
            </Button>
          </div>
        </Empty>
      ) : (
      <div className="hash-analyzer">
        {/* Report Configuration Controls */}
        <section className="analyzer-card">
          <div className="section-title" style={{ paddingTop: 0 }}>
            <h2>
              <FileText size={17} /> Report Scope & Examiner Parameters
            </h2>
            <span className="status-badge status-active">LIVE REPORT BUILDER</span>
          </div>

          <div className="form-row">
            <label className="field-label">
              Select Investigation Case for Report
              <select value={selectedCaseId} onChange={(e) => setSelectedCaseId(e.target.value)}>
                <option value="ALL">All Investigations — Master Report ({cases.length} cases)</option>
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.case_number}) · {c.status}
                  </option>
                ))}
              </select>
            </label>

            <label className="field-label">
              Lead Forensic Examiner Name
              <input
                type="text"
                value={examinerName}
                onChange={(e) => setExaminerName(e.target.value)}
                placeholder={selectedCase?.investigator || cases[0]?.investigator || 'Enter your name…'}
              />
            </label>
          </div>

          <label className="field-label">
            Forensic Laboratory / Organization
            <input
              type="text"
              value={agencyName}
              onChange={(e) => setAgencyName(e.target.value)}
              placeholder="Enter your lab, organization, or course name…"
            />
          </label>

          <div className="form-row">
            <label className="field-label">
              Executive Summary Narrative
              <textarea
                value={executiveSummary}
                onChange={(e) => setExecutiveSummary(e.target.value)}
                placeholder="Summarize the scope and background of your investigation…"
              />
            </label>
            <label className="field-label">
              Forensic Conclusions & Verification Attestation
              <textarea
                value={conclusionsText}
                onChange={(e) => setConclusionsText(e.target.value)}
                placeholder="Enter your verified forensic findings and conclusions…"
              />
            </label>
          </div>
        </section>

        {/* Unverified / Mismatch Alert Banner (NWIT 263 Rubric Guardrail) */}
        {mismatchEvidenceCount > 0 ? (
          <div className="integrity-banner mismatch" style={{ marginTop: 0 }}>
            <ShieldAlert size={20} />
            <div>
              <strong>INTEGRITY / VALIDATION MISMATCH WARNING ({mismatchEvidenceCount} ITEM)</strong>
              <p>
                This report contains evidence items flagged as MISMATCH during independent verification. Mismatched findings are explicitly highlighted below and must not be presented as verified facts.
              </p>
            </div>
          </div>
        ) : unverifiedEvidenceCount > 0 ? (
          <div className="integrity-banner review" style={{ marginTop: 0 }}>
            <AlertTriangle size={20} />
            <div>
              <strong>UNVERIFIED EVIDENCE NOTICE ({unverifiedEvidenceCount} PENDING VERIFICATION)</strong>
              <p>
                {unverifiedEvidenceCount} evidence item(s) in this report have not yet been independently verified via an external tool. Per forensic standards, unverified items are separated from verified findings below.
              </p>
            </div>
          </div>
        ) : reportEvidence.length > 0 ? (
          <div className="integrity-banner match" style={{ marginTop: 0 }}>
            <CheckCircle2 size={20} />
            <div>
              <strong>ALL PRESERVED EVIDENCE INDEPENDENTLY VERIFIED ({verifiedEvidenceCount}/{reportEvidence.length})</strong>
              <p>
                Every evidence item in this report has been independently verified against an approved external tool and recorded in the 9-Column Validation Log.
              </p>
            </div>
          </div>
        ) : null}

        {/* Printable Live Report Preview Card */}
        <section className="analyzer-card">
          <div className="section-title" style={{ paddingTop: 0 }}>
            <div>
              <span className="eyebrow">OFFICIAL DIGITAL FORENSICS REPORT</span>
              <h2 style={{ fontSize: '18px', marginTop: 4 }}>{reportTitle}</h2>
            </div>
            <span className="mono muted" style={{ fontSize: '10px' }}>
              UTC: {reportDateUtc}
            </span>
          </div>

          <div className="exif-fields-grid">
            <div className="exif-field-row">
              <span className="exif-label">Lead Examiner</span>
              <strong>{effectiveExaminer}</strong>
            </div>
            <div className="exif-field-row">
              <span className="exif-label">Laboratory / Organization</span>
              <span>{effectiveAgency}</span>
            </div>
            <div className="exif-field-row">
              <span className="exif-label">Cases Included</span>
              <span className="mono">{reportCases.length}</span>
            </div>
            <div className="exif-field-row">
              <span className="exif-label">Evidence Verification Breakdown</span>
              <span className="mono">
                {verifiedEvidenceCount} Verified · {unverifiedEvidenceCount} Pending · {mismatchEvidenceCount} Mismatch
              </span>
            </div>
          </div>

          {/* Section 1: Executive Summary */}
          <div className="verify-box">
            <div className="detail-label">SECTION 1 · EXECUTIVE SUMMARY</div>
            <p style={{ fontSize: '12px', lineHeight: 1.65 }}>{effectiveSummary}</p>
          </div>

          {/* Section 2: Preserved Evidence Inventory */}
          <div className="verify-box">
            <div className="detail-label">
              SECTION 2 · PRESERVED EVIDENCE LOCKER INVENTORY ({reportEvidence.length} ITEMS)
            </div>
            {reportEvidence.length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>EVIDENCE ID</th>
                      <th>FILENAME</th>
                      <th>CASE</th>
                      <th>SIZE</th>
                      <th>BASELINE SHA-256 DIGEST</th>
                      <th>VALIDATION STATUS</th>
                      <th>UPLOADED (UTC)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportEvidence.map((ev) => {
                      const code = getEvidenceCode(ev.id, evidence);
                      const c = cases.find((cs) => cs.id === ev.case_id);
                      return (
                        <tr key={ev.id}>
                          <td>
                            <span className="algo-tag">{code}</span>
                          </td>
                          <td>
                            <strong>{ev.filename}</strong>
                          </td>
                          <td className="mono">{c?.case_number ?? 'DB-LOCAL'}</td>
                          <td className="mono">{(ev.file_size / 1024).toFixed(1)} KB</td>
                          <td className="mono" style={{ fontSize: '9.5px', maxWidth: 240, wordBreak: 'break-all' }}>
                            {ev.sha256}
                          </td>
                          <td>
                            <span
                              className={`status-badge ${
                                ev.validation_status === 'VERIFIED'
                                  ? 'status-active'
                                  : ev.validation_status === 'MISMATCH'
                                  ? 'status-mismatch'
                                  : ev.validation_status === 'NEEDS REVIEW'
                                  ? 'status-review'
                                  : ''
                              }`}
                            >
                              {ev.validation_status}
                            </span>
                          </td>
                          <td className="mono" style={{ fontSize: '9.5px' }}>
                            {ev.uploaded_at}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="muted" style={{ fontSize: '11px' }}>
                No evidence files in this scope yet. Upload evidence in the{' '}
                <Link to="/evidence" style={{ color: 'var(--violet)', textDecoration: 'underline' }}>
                  Evidence Locker
                </Link>
                .
              </p>
            )}
          </div>

          {/* Section 3: 9-Column Independent Validation Log */}
          <div className="verify-box">
            <div className="detail-label">
              SECTION 3 · 9-COLUMN INDEPENDENT VALIDATION LOG ({reportValidations.length} VERIFICATIONS)
            </div>
            {reportValidations.length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>1. EVIDENCE ID</th>
                      <th>2. FILENAME</th>
                      <th>3. MODULE</th>
                      <th>4. FIELD / ALGO</th>
                      <th>5. DEADBYTE RESULT</th>
                      <th>6. EXTERNAL TOOL</th>
                      <th>7. EXTERNAL RESULT</th>
                      <th>8. STATUS</th>
                      <th>9. VALIDATOR & TIME</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportValidations.map((v) => (
                      <tr key={v.id}>
                        <td>
                          <span className="algo-tag">{v.evidence_code}</span>
                        </td>
                        <td>
                          <strong>{v.filename}</strong>
                        </td>
                        <td>{v.module}</td>
                        <td className="mono">{v.algorithm ?? 'Standard'}</td>
                        <td className="mono" style={{ fontSize: '9.5px', maxWidth: 180, wordBreak: 'break-all' }}>
                          {v.platform_result}
                        </td>
                        <td>{v.independent_tool}</td>
                        <td className="mono" style={{ fontSize: '9.5px', maxWidth: 180, wordBreak: 'break-all' }}>
                          {v.independent_result}
                        </td>
                        <td>
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
                        </td>
                        <td className="mono" style={{ fontSize: '9.5px' }}>
                          {v.validator}
                          <small>{new Date(v.created_at).toLocaleString()}</small>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="muted" style={{ fontSize: '11px' }}>
                No independent validations recorded for this case scope yet. Run any analyzer in the Forensic Toolkit to log a verification.
              </p>
            )}
          </div>

          {/* Section 4: Chain of Custody Activity Log */}
          <div className="verify-box">
            <div className="detail-label">
              SECTION 4 · CHAIN OF CUSTODY & AUDIT TRAIL ({reportActivity.length} EVENTS)
            </div>
            {reportActivity.length > 0 ? (
              <div className="hash-list">
                {reportActivity.slice(0, 15).map((a) => (
                  <div key={a.id} className="hash-item">
                    <div className="hash-item-top">
                      <strong>{a.action}</strong>
                      <span className="mono muted" style={{ fontSize: '9.5px' }}>
                        {a.created_at}
                      </span>
                    </div>
                    <div className="mono" style={{ fontSize: '10px', opacity: 0.9 }}>
                      {a.detail}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="muted" style={{ fontSize: '11px' }}>
                No chain-of-custody activity recorded yet.
              </p>
            )}
          </div>

          {/* Section 5: Examiner Conclusions & Attestation */}
          <div className="verify-box">
            <div className="detail-label">SECTION 5 · FORENSIC CONCLUSIONS & EXAMINER ATTESTATION</div>
            <p style={{ fontSize: '12px', lineHeight: 1.65 }}>{effectiveConclusions}</p>
          </div>
        </section>
      </div>
      )}
    </div>
  );
}
