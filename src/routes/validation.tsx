import { createFileRoute, Link } from '@tanstack/react-router';
import { useState } from 'react';
import { PageHeading, Empty, useWorkspace } from '@/components/deadbyte/workspace';
import { Button } from '@/components/ui/button';
import { ShieldCheck, Hash, ArrowUpRight } from 'lucide-react';

export const Route = createFileRoute('/validation')({
  head: () => ({
    meta: [
      { title: 'Validation Log — DeadByte' },
      { name: 'description', content: 'Independent human validation of forensic evidence.' },
      { property: 'og:title', content: 'Validation Log — DeadByte' },
      {
        property: 'og:description',
        content: 'Independent human validation of forensic evidence.',
      },
      { property: 'og:type', content: 'website' },
      { name: 'twitter:card', content: 'summary_large_image' },
    ],
  }),
  component: ValidationLogPage,
});

function ValidationLogPage() {
  const { validations } = useWorkspace();
  const [moduleFilter, setModuleFilter] = useState('All modules');
  const [statusFilter, setStatusFilter] = useState('All statuses');

  const filtered = validations.filter(
    v =>
      (moduleFilter === 'All modules' || v.module === moduleFilter) &&
      (statusFilter === 'All statuses' || v.status === statusFilter),
  );

  return (
    <div className="page">
      <PageHeading
        eyebrow="INVESTIGATION · SECTION 9.2 DELIVERABLE"
        title="Validation Log"
        description="Documented independent human validation of platform results against external forensic tools."
      >
        <Button asChild>
          <Link to="/tools/$tool" params={{ tool: 'hash' }}>
            <Hash />
            Open Hash Analyzer
          </Link>
        </Button>
      </PageHeading>

      <div className="toolbar">
        <select
          aria-label="Filter by module"
          value={moduleFilter}
          onChange={e => setModuleFilter(e.target.value)}
        >
          <option>All modules</option>
          <option>Hash</option>
          <option>EXIF</option>
          <option>Registry</option>
          <option>PCAP</option>
          <option>SQLite</option>
          <option>Timeline</option>
        </select>

        <select
          aria-label="Filter by validation status"
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
        >
          <option>All statuses</option>
          <option>VERIFIED</option>
          <option>MISMATCH</option>
          <option>NEEDS REVIEW</option>
        </select>

        <span className="muted">{filtered.length} validation records</span>
      </div>

      {filtered.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>CASE / EVIDENCE ID</th>
                <th>MODULE</th>
                <th>PLATFORM RESULT</th>
                <th>INDEPENDENT TOOL</th>
                <th>INDEPENDENT RESULT</th>
                <th>STATUS</th>
                <th>VALIDATOR</th>
                <th>DATE</th>
                <th>NOTES</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(v => (
                <tr key={v.id}>
                  <td>
                    <strong className="mono">
                      {v.case_number} · {v.evidence_code}
                    </strong>
                    <small>{v.filename}</small>
                  </td>
                  <td>
                    <span className="algo-tag">
                      {v.module}
                      {v.algorithm ? ` (${v.algorithm})` : ''}
                    </span>
                  </td>
                  <td>
                    <span
                      className="mono"
                      style={{
                        fontSize: 9,
                        display: 'block',
                        maxWidth: 210,
                        overflowWrap: 'anywhere',
                      }}
                    >
                      {v.platform_result}
                    </span>
                  </td>
                  <td>{v.independent_tool}</td>
                  <td>
                    <span
                      className="mono"
                      style={{
                        fontSize: 9,
                        display: 'block',
                        maxWidth: 210,
                        overflowWrap: 'anywhere',
                      }}
                    >
                      {v.independent_result}
                    </span>
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
                  <td>
                    <strong>{v.validator}</strong>
                  </td>
                  <td>{new Date(v.created_at).toLocaleString()}</td>
                  <td style={{ maxWidth: 230 }}>{v.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty
          icon={ShieldCheck}
          title="No independent validation records yet"
          description="Use the Hash Analyzer (or another forensic module) to compare DeadByte's extracted output against an independent tool (Get-FileHash, certutil, sha256sum, ExifTool, etc.) and record your verification."
        >
          <Button asChild variant="outline" size="sm">
            <Link to="/tools/$tool" params={{ tool: 'hash' }}>
              <Hash />
              Go to Hash Analyzer
              <ArrowUpRight />
            </Link>
          </Button>
        </Empty>
      )}
    </div>
  );
}
