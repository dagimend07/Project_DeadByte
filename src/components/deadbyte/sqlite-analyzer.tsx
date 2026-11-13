import { useState, useRef, useEffect } from 'react';
import { Link } from '@tanstack/react-router';
import {
  useWorkspace,
  getLocalEvidenceBlob,
  getEvidenceCode,
  markLocalEvidenceProcessed,
  saveValidationRecord,
  Empty,
} from './workspace';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import {
  Database,
  Upload,
  Copy,
  ShieldCheck,
  ShieldAlert,
  Archive,
  Terminal,
  ArrowUpRight,
  FileWarning,
  Bot,
  Table as TableIcon,
  FileCode2,
  Sparkles,
  Download,
  Search,
} from 'lucide-react';

export interface SqliteColumnDef {
  name: string;
  type: string;
  isPrimaryKey: boolean;
}

export interface SqliteSchemaObject {
  type: 'table' | 'index' | 'view' | 'trigger';
  name: string;
  tblName: string;
  rootPage: number;
  sql: string;
  columns: SqliteColumnDef[];
  rowCount: number;
  sourceRef: string;
}

export interface SqliteExtractedRow {
  tableName: string;
  rowId: number;
  values: Record<string, string | number | null>;
  sourceRef: string;
  forensicFlag?: string;
}

export interface ParsedSqliteAnalysis {
  supported: boolean;
  corrupted: boolean;
  errorMessage?: string;
  detectedFormat: string;
  magicBytesHex: string;
  extensionName: string;
  extensionMismatch: boolean;
  mismatchReason?: string;
  // SQLite 100-byte Header Fields
  sqliteVersionString: string | null;
  pageSize: number | null;
  pageCount: number | null;
  textEncoding: string | null;
  schemaCookie: number | null;
  changeCounter: number | null;
  freelistPageCount: number | null;
  userVersion: number | null;
  applicationId: string | null;
  writeReadVersions: string | null;
  // Extracted Catalog & Records
  schemaObjects: SqliteSchemaObject[];
  tables: SqliteSchemaObject[];
  rowsByTable: Record<string, SqliteExtractedRow[]>;
  allRows: SqliteExtractedRow[];
  anomalies: string[];
}

const SQLITE_INDEPENDENT_TOOLS = [
  'DB Browser for SQLite (sqlitebrowser)',
  'SQLite3 CLI (sqlite3 FILE)',
  'Autopsy SQLite Viewer',
  'Axiom / Forensic Explorer SQLite Parser',
  'Other Approved SQLite Tool',
] as const;

function bytesToHex(bytes: Uint8Array, max = 8): string {
  return Array.from(bytes.slice(0, max))
    .map(b => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

function readAscii(view: DataView, start: number, length: number): string {
  let out = '';
  const end = Math.min(view.byteLength, start + length);
  for (let i = start; i < end; i++) {
    const code = view.getUint8(i);
    if (code === 0) break;
    if (code >= 32 && code <= 126) out += String.fromCharCode(code);
  }
  return out.trim();
}

/**
 * Reads a SQLite big-endian variable-length integer (varint, 1 to 9 bytes).
 */
function readSqliteVarint(
  bytes: Uint8Array,
  offset: number,
): { value: number; byteLength: number } {
  let result = 0;
  for (let i = 0; i < 8; i++) {
    if (offset + i >= bytes.length) {
      return { value: result, byteLength: i + 1 };
    }
    const b = bytes[offset + i];
    result = result * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      return { value: result, byteLength: i + 1 };
    }
  }
  if (offset + 8 < bytes.length) {
    result = result * 256 + bytes[offset + 8];
  }
  return { value: result, byteLength: 9 };
}

/**
 * Encodes a non-negative integer into a SQLite big-endian varint.
 */
function encodeSqliteVarint(val: number): number[] {
  if (val < 0x80) return [val & 0x7f];
  const out: number[] = [val & 0x7f];
  let v = Math.floor(val / 128);
  while (v > 0) {
    out.unshift((v & 0x7f) | 0x80);
    v = Math.floor(v / 128);
  }
  return out;
}

/**
 * Parses column definitions from a CREATE TABLE SQL statement.
 */
function parseColumnsFromCreateSql(sql: string): SqliteColumnDef[] {
  const openParen = sql.indexOf('(');
  const closeParen = sql.lastIndexOf(')');
  if (openParen === -1 || closeParen === -1 || closeParen <= openParen) {
    return [];
  }
  const body = sql.slice(openParen + 1, closeParen).trim();

  // Split by top-level commas
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    if (ch === ',' && depth === 0) {
      parts.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) parts.push(current.trim());

  const cols: SqliteColumnDef[] = [];
  for (const rawPart of parts) {
    const clean = rawPart.replace(/\s+/g, ' ').trim();
    if (!clean) continue;
    const upper = clean.toUpperCase();
    if (
      upper.startsWith('PRIMARY KEY') ||
      upper.startsWith('FOREIGN KEY') ||
      upper.startsWith('UNIQUE') ||
      upper.startsWith('CONSTRAINT') ||
      upper.startsWith('CHECK')
    ) {
      continue;
    }

    // Match quoted or unquoted column name
    const match = clean.match(/^(?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([A-Za-z0-9_]+))\s*(.*)$/);
    if (!match) continue;
    const colName = match[1] || match[2] || match[3] || match[4];
    const rest = (match[5] || '').trim();
    const restTokens = rest.split(/\s+/).filter(Boolean);
    const colType =
      restTokens[0] &&
      !['PRIMARY', 'NOT', 'UNIQUE', 'DEFAULT', 'REFERENCES', 'CHECK'].includes(
        restTokens[0].toUpperCase(),
      )
        ? restTokens[0].toUpperCase()
        : 'TEXT';
    const isPk = /PRIMARY\s+KEY/i.test(rest);
    cols.push({
      name: colName,
      type: colType,
      isPrimaryKey: isPk,
    });
  }
  return cols;
}

/**
 * Decodes a single SQLite Record Format value given its serial type.
 */
function readSerialValue(
  bytes: Uint8Array,
  view: DataView,
  offset: number,
  serialType: number,
  encoding: 'utf-8' | 'utf-16le' | 'utf-16be',
): { value: string | number | null; byteLen: number } {
  if (serialType === 0) return { value: null, byteLen: 0 };
  if (serialType === 8) return { value: 0, byteLen: 0 };
  if (serialType === 9) return { value: 1, byteLen: 0 };

  if (serialType === 1) {
    if (offset + 1 > bytes.length) return { value: null, byteLen: 0 };
    return { value: view.getInt8(offset), byteLen: 1 };
  }
  if (serialType === 2) {
    if (offset + 2 > bytes.length) return { value: null, byteLen: 0 };
    return { value: view.getInt16(offset, false), byteLen: 2 };
  }
  if (serialType === 3) {
    if (offset + 3 > bytes.length) return { value: null, byteLen: 0 };
    let v = (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
    if (v & 0x800000) v -= 0x1000000;
    return { value: v, byteLen: 3 };
  }
  if (serialType === 4) {
    if (offset + 4 > bytes.length) return { value: null, byteLen: 0 };
    return { value: view.getInt32(offset, false), byteLen: 4 };
  }
  if (serialType === 5) {
    if (offset + 6 > bytes.length) return { value: null, byteLen: 0 };
    const hi = view.getInt16(offset, false);
    const lo = view.getUint32(offset + 2, false);
    return { value: hi * 0x100000000 + lo, byteLen: 6 };
  }
  if (serialType === 6) {
    if (offset + 8 > bytes.length) return { value: null, byteLen: 0 };
    const big = view.getBigInt64(offset, false);
    const num = Number(big);
    return {
      value: Number.isSafeInteger(num) ? num : big.toString(),
      byteLen: 8,
    };
  }
  if (serialType === 7) {
    if (offset + 8 > bytes.length) return { value: null, byteLen: 0 };
    return { value: Number(view.getFloat64(offset, false).toFixed(6)), byteLen: 8 };
  }

  // BLOB: even serialType >= 12 -> (N - 12) / 2 bytes
  if (serialType >= 12 && serialType % 2 === 0) {
    const len = (serialType - 12) / 2;
    if (offset + len > bytes.length) return { value: null, byteLen: 0 };
    const slice = bytes.slice(offset, offset + Math.min(len, 16));
    const hexPreview = Array.from(slice)
      .map(b => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ');
    return {
      value: `BLOB (${len} B): ${hexPreview}${len > 16 ? '…' : ''}`,
      byteLen: len,
    };
  }

  // TEXT: odd serialType >= 13 -> (N - 13) / 2 bytes
  if (serialType >= 13 && serialType % 2 === 1) {
    const len = (serialType - 13) / 2;
    if (offset + len > bytes.length) return { value: null, byteLen: 0 };
    const slice = bytes.slice(offset, offset + len);
    try {
      const str = new TextDecoder(encoding).decode(slice).replace(/\0+$/g, '');
      return { value: str, byteLen: len };
    } catch {
      return { value: '', byteLen: len };
    }
  }

  return { value: null, byteLen: 0 };
}

/**
 * Parses a SQLiteRecord payload into an array of column values.
 */
function parseSqliteRecordPayload(
  bytes: Uint8Array,
  view: DataView,
  payloadStart: number,
  payloadLength: number,
  encoding: 'utf-8' | 'utf-16le' | 'utf-16be',
): (string | number | null)[] {
  const payloadEnd = Math.min(bytes.length, payloadStart + payloadLength);
  if (payloadStart >= payloadEnd) return [];

  const hdrVarint = readSqliteVarint(bytes, payloadStart);
  const headerSize = hdrVarint.value;
  const headerEnd = Math.min(payloadEnd, payloadStart + headerSize);

  const serialTypes: number[] = [];
  let hPos = payloadStart + hdrVarint.byteLength;
  while (hPos < headerEnd) {
    const st = readSqliteVarint(bytes, hPos);
    serialTypes.push(st.value);
    hPos += st.byteLength;
    if (st.byteLength === 0) break;
  }

  const values: (string | number | null)[] = [];
  let bodyPos = payloadStart + headerSize;
  for (const st of serialTypes) {
    if (bodyPos > payloadEnd) {
      values.push(null);
      continue;
    }
    const decoded = readSerialValue(bytes, view, bodyPos, st, encoding);
    values.push(decoded.value);
    bodyPos += decoded.byteLen;
  }
  return values;
}

/**
 * Traverses a SQLite Table B-Tree (Leaf Page 0x0D and Interior Page 0x05)
 * and invokes `onRecord(rowId, values)` for every row found.
 */
function traverseTableBTreePage(
  bytes: Uint8Array,
  view: DataView,
  pageNumber: number,
  pageSize: number,
  encoding: 'utf-8' | 'utf-16le' | 'utf-16be',
  visitedPages: Set<number>,
  onRecord: (rowId: number, values: (string | number | null)[]) => void,
  maxRows = 500,
  currentCount = { count: 0 },
) {
  if (
    pageNumber < 1 ||
    visitedPages.has(pageNumber) ||
    currentCount.count >= maxRows
  ) {
    return;
  }
  visitedPages.add(pageNumber);

  const pageStart = (pageNumber - 1) * pageSize;
  if (pageStart + 8 > bytes.length) return;

  // Page 1 has the 100-byte database header before the B-Tree page header
  const btreeHeaderOffset = pageNumber === 1 ? pageStart + 100 : pageStart;
  if (btreeHeaderOffset + 8 > bytes.length) return;

  const pageType = bytes[btreeHeaderOffset];

  // 0x0D = Leaf Table B-Tree Page
  if (pageType === 0x0d) {
    const cellCount = view.getUint16(btreeHeaderOffset + 3, false);
    const cellPtrArrayStart = btreeHeaderOffset + 8;

    for (let i = 0; i < cellCount; i++) {
      if (currentCount.count >= maxRows) break;
      const ptrPos = cellPtrArrayStart + i * 2;
      if (ptrPos + 2 > bytes.length) break;
      const cellRelOffset = view.getUint16(ptrPos, false);
      const cellAbsOffset = pageStart + cellRelOffset;
      if (cellAbsOffset >= pageStart + pageSize || cellAbsOffset >= bytes.length) {
        continue;
      }

      const payloadLenVar = readSqliteVarint(bytes, cellAbsOffset);
      const rowIdVar = readSqliteVarint(
        bytes,
        cellAbsOffset + payloadLenVar.byteLength,
      );
      const payloadStart =
        cellAbsOffset + payloadLenVar.byteLength + rowIdVar.byteLength;

      const values = parseSqliteRecordPayload(
        bytes,
        view,
        payloadStart,
        payloadLenVar.value,
        encoding,
      );
      currentCount.count++;
      onRecord(rowIdVar.value, values);
    }
  } else if (pageType === 0x05) {
    // 0x05 = Interior Table B-Tree Page
    if (btreeHeaderOffset + 12 > bytes.length) return;
    const cellCount = view.getUint16(btreeHeaderOffset + 3, false);
    const rightMostPage = view.getUint32(btreeHeaderOffset + 8, false);
    const cellPtrArrayStart = btreeHeaderOffset + 12;

    for (let i = 0; i < cellCount; i++) {
      if (currentCount.count >= maxRows) break;
      const ptrPos = cellPtrArrayStart + i * 2;
      if (ptrPos + 2 > bytes.length) break;
      const cellRelOffset = view.getUint16(ptrPos, false);
      const cellAbsOffset = pageStart + cellRelOffset;
      if (cellAbsOffset + 4 > bytes.length) continue;

      const leftChildPage = view.getUint32(cellAbsOffset, false);
      traverseTableBTreePage(
        bytes,
        view,
        leftChildPage,
        pageSize,
        encoding,
        visitedPages,
        onRecord,
        maxRows,
        currentCount,
      );
    }

    if (currentCount.count < maxRows && rightMostPage > 0) {
      traverseTableBTreePage(
        bytes,
        view,
        rightMostPage,
        pageSize,
        encoding,
        visitedPages,
        onRecord,
        maxRows,
        currentCount,
      );
    }
  }
}

/**
 * Encodes a single SQLite Record payload from an array of JS values (strings or integers).
 */
function buildSqliteRecordBytes(values: (string | number | null)[]): Uint8Array {
  const serialTypes: number[] = [];
  const bodyParts: Uint8Array[] = [];
  const enc = new TextEncoder();

  for (const val of values) {
    if (val === null || val === undefined) {
      serialTypes.push(0);
    } else if (typeof val === 'number') {
      if (val === 0) {
        serialTypes.push(8);
      } else if (val === 1) {
        serialTypes.push(9);
      } else if (val >= -128 && val <= 127) {
        serialTypes.push(1);
        const b = new Uint8Array(1);
        new DataView(b.buffer).setInt8(0, val);
        bodyParts.push(b);
      } else if (val >= -32768 && val <= 32767) {
        serialTypes.push(2);
        const b = new Uint8Array(2);
        new DataView(b.buffer).setInt16(0, val, false);
        bodyParts.push(b);
      } else {
        serialTypes.push(4);
        const b = new Uint8Array(4);
        new DataView(b.buffer).setInt32(0, val, false);
        bodyParts.push(b);
      }
    } else {
      const strBytes = enc.encode(String(val));
      serialTypes.push(strBytes.length * 2 + 13);
      bodyParts.push(strBytes);
    }
  }

  const stVarints = serialTypes.flatMap(st => encodeSqliteVarint(st));
  const hdrSize = stVarints.length + 1;
  const headerBytes = new Uint8Array([hdrSize, ...stVarints]);
  const bodyLen = bodyParts.reduce((acc, p) => acc + p.length, 0);

  const out = new Uint8Array(headerBytes.length + bodyLen);
  out.set(headerBytes, 0);
  let pos = headerBytes.length;
  for (const part of bodyParts) {
    out.set(part, pos);
    pos += part.length;
  }
  return out;
}

/**
 * Writes a Leaf Table B-Tree Page (0x0D) with the given records into `dbBytes`.
 */
function writeLeafTablePage(
  dbBytes: Uint8Array,
  pageNumber: number,
  pageSize: number,
  rows: { rowId: number; values: (string | number | null)[] }[],
) {
  const pageStart = (pageNumber - 1) * pageSize;
  const view = new DataView(dbBytes.buffer);
  const btreeHdr = pageNumber === 1 ? pageStart + 100 : pageStart;

  dbBytes[btreeHdr] = 0x0d; // Leaf Table B-Tree
  view.setUint16(btreeHdr + 1, 0, false); // First freeblock
  view.setUint16(btreeHdr + 3, rows.length, false); // Number of cells

  let contentCursor = pageSize; // Grows downward from end of page
  const ptrArrayStart = btreeHdr + 8;

  for (let i = 0; i < rows.length; i++) {
    const recPayload = buildSqliteRecordBytes(rows[i].values);
    const lenVar = encodeSqliteVarint(recPayload.length);
    const idVar = encodeSqliteVarint(rows[i].rowId);
    const cellLen = lenVar.length + idVar.length + recPayload.length;

    contentCursor -= cellLen;
    const cellAbs = pageStart + contentCursor;
    dbBytes.set(lenVar, cellAbs);
    dbBytes.set(idVar, cellAbs + lenVar.length);
    dbBytes.set(recPayload, cellAbs + lenVar.length + idVar.length);

    view.setUint16(ptrArrayStart + i * 2, contentCursor, false);
  }

  view.setUint16(btreeHdr + 5, contentCursor, false); // Cell content area start
  dbBytes[btreeHdr + 7] = 0; // Fragmented free bytes
}

/**
 * Generates a real, standards-compliant 4-page (16,384-byte) SQLite 3 binary database file
 * (`Browser_Forensic_Artifacts.sqlite`) that opens in `sqlite3` CLI, DB Browser for SQLite,
 * and Autopsy, containing 3 forensic tables (`urls`, `downloads`, `credentials_audit`).
 */
export function createSampleForensicSqliteFile(): File {
  const pageSize = 4096;
  const pageCount = 4;
  const dbBytes = new Uint8Array(pageSize * pageCount);
  const view = new DataView(dbBytes.buffer);
  const enc = new TextEncoder();

  // 100-byte SQLite 3 Database Header on Page 1
  dbBytes.set(enc.encode('SQLite format 3\0'), 0);
  view.setUint16(16, pageSize, false); // Page size = 4096
  dbBytes[18] = 1; // File format write version
  dbBytes[19] = 1; // File format read version
  dbBytes[20] = 0; // Reserved space
  dbBytes[21] = 64; // Max embedded payload fraction
  dbBytes[22] = 32; // Min embedded payload fraction
  dbBytes[23] = 32; // Leaf payload fraction
  view.setUint32(24, 14, false); // File change counter
  view.setUint32(28, pageCount, false); // Database size in pages (4)
  view.setUint32(32, 0, false); // First freelist trunk page
  view.setUint32(36, 0, false); // Total freelist pages
  view.setUint32(40, 3, false); // Schema cookie
  view.setUint32(44, 4, false); // Schema format number (4)
  view.setUint32(56, 1, false); // Text encoding: 1 = UTF-8
  view.setUint32(60, 2026, false); // User version
  view.setUint32(68, 0x44425954, false); // Application ID ('DBYT')
  view.setUint32(92, 14, false); // Version-valid-for
  view.setUint32(96, 3045001, false); // SQLite version 3.45.1

  // Page 1: sqlite_master catalog (3 tables on rootpages 2, 3, 4)
  writeLeafTablePage(dbBytes, 1, pageSize, [
    {
      rowId: 1,
      values: [
        'table',
        'urls',
        'urls',
        2,
        'CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_utc TEXT)',
      ],
    },
    {
      rowId: 2,
      values: [
        'table',
        'downloads',
        'downloads',
        3,
        'CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, source_url TEXT, total_bytes INTEGER, start_time_utc TEXT, danger_type TEXT)',
      ],
    },
    {
      rowId: 3,
      values: [
        'table',
        'session_logins',
        'session_logins',
        4,
        'CREATE TABLE session_logins (id INTEGER PRIMARY KEY, origin_url TEXT, username_value TEXT, signon_realm TEXT, date_created_utc TEXT)',
      ],
    },
  ]);

  // Page 2: `urls` table records
  writeLeafTablePage(dbBytes, 2, pageSize, [
    {
      rowId: 1,
      values: [
        null, // INTEGER PRIMARY KEY alias uses rowId
        'https://portal.corp-internal.local/admin/export',
        'Internal HR & Payroll Export Portal',
        19,
        '2026-10-22 13:14:08 UTC',
      ],
    },
    {
      rowId: 2,
      values: [
        null,
        'https://mega-drop-staging.xyz/upload/archive',
        'External Dropzone — Anonymous File Upload',
        4,
        '2026-10-22 13:19:45 UTC',
      ],
    },
    {
      rowId: 3,
      values: [
        null,
        'https://github.com/attacker-ops/stage2-beacon/releases',
        'Release v2.4 — PowerShell Persistence Kit',
        2,
        '2026-10-22 13:22:11 UTC',
      ],
    },
    {
      rowId: 4,
      values: [
        null,
        'https://www.google.com/search?q=how+to+clear+windows+event+logs+wevtutil',
        'how to clear windows event logs wevtutil - Google Search',
        1,
        '2026-10-22 13:28:50 UTC',
      ],
    },
  ]);

  // Page 3: `downloads` table records
  writeLeafTablePage(dbBytes, 3, pageSize, [
    {
      rowId: 1,
      values: [
        null,
        'C:\\Users\\arivera\\Downloads\\Payroll_2026_Backup.xlsx',
        'https://portal.corp-internal.local/admin/export/Payroll_2026_Backup.xlsx',
        482910,
        '2026-10-22 13:15:02 UTC',
        'NOT_DANGEROUS',
      ],
    },
    {
      rowId: 2,
      values: [
        null,
        'C:\\Users\\arivera\\AppData\\Local\\Temp\\stage2_beacon.ps1',
        'https://github.com/attacker-ops/stage2-beacon/releases/download/v2.4/stage2_beacon.ps1',
        18432,
        '2026-10-22 13:23:04 UTC',
        'DANGEROUS_FILE_COMPROMISE',
      ],
    },
    {
      rowId: 3,
      values: [
        null,
        'C:\\Users\\Public\\Downloads\\svchost_helper.exe',
        'https://mega-drop-staging.xyz/payloads/svchost_helper.exe',
        942080,
        '2026-10-22 13:25:19 UTC',
        'POTENTIALLY_UNWANTED',
      ],
    },
  ]);

  // Page 4: `session_logins` table records
  writeLeafTablePage(dbBytes, 4, pageSize, [
    {
      rowId: 1,
      values: [
        null,
        'https://portal.corp-internal.local/login',
        'arivera@corp-internal.local',
        'https://portal.corp-internal.local/',
        '2026-09-04 09:12:00 UTC',
      ],
    },
    {
      rowId: 2,
      values: [
        null,
        'https://mega-drop-staging.xyz/auth',
        'ghost_exfil_99',
        'https://mega-drop-staging.xyz/',
        '2026-10-22 13:18:30 UTC',
      ],
    },
  ]);

  return new File([dbBytes], 'Browser_Forensic_Artifacts.sqlite', {
    type: 'application/vnd.sqlite3',
    lastModified: Date.now(),
  });
}

/**
 * Deterministic binary parser for SQLite 3 database files (.sqlite, .db, .sqlite3).
 * Inspects the 100-byte database header, parses sqlite_master on Page 1,
 * and traverses each table's B-Tree root page to extract records with rowid attribution.
 */
export function parseSqliteEvidenceBuffer(
  buffer: ArrayBuffer,
  filename: string,
): ParsedSqliteAnalysis {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const extMatch = filename.toLowerCase().match(/\.([a-z0-9]+)$/);
  const ext = extMatch ? extMatch[1] : 'none';
  const magicHex = bytesToHex(bytes, 8);
  const anomalies: string[] = [];
  const schemaObjects: SqliteSchemaObject[] = [];
  const rowsByTable: Record<string, SqliteExtractedRow[]> = {};
  const allRows: SqliteExtractedRow[] = [];

  const base: ParsedSqliteAnalysis = {
    supported: false,
    corrupted: false,
    detectedFormat: 'Unknown Binary',
    magicBytesHex: magicHex,
    extensionName: `.${ext}`,
    extensionMismatch: false,
    sqliteVersionString: null,
    pageSize: null,
    pageCount: null,
    textEncoding: null,
    schemaCookie: null,
    changeCounter: null,
    freelistPageCount: null,
    userVersion: null,
    applicationId: null,
    writeReadVersions: null,
    schemaObjects,
    tables: [],
    rowsByTable,
    allRows,
    anomalies,
  };

  if (bytes.length === 0) {
    return {
      ...base,
      corrupted: true,
      errorMessage: 'Empty file (0 bytes). Cannot extract SQLite database artifacts.',
    };
  }

  // Check 16-byte magic header: "SQLite format 3\0" (53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00)
  const magicAscii = bytes.length >= 15 ? readAscii(view, 0, 15) : '';
  const isSqlite3 = magicAscii === 'SQLite format 3' && bytes[15] === 0x00;

  if (!isSqlite3) {
    if (['sqlite', 'sqlite3', 'db', 'db3', 's3db'].includes(ext)) {
      base.extensionMismatch = true;
      base.mismatchReason = `RENAMED / SPOOFED EXTENSION: File is named ".${ext}", but its binary header (${magicHex}) is NOT "SQLite format 3\\0".`;
      anomalies.push(base.mismatchReason);
    }
    base.supported = false;
    base.errorMessage = base.extensionMismatch
      ? base.mismatchReason
      : `UNSUPPORTED FILE TYPE: Binary signature (${magicHex}) is not a valid SQLite 3 database ("SQLite format 3\\0"). No database tables or rows were fabricated.`;
    return base;
  }

  base.supported = true;
  base.detectedFormat = 'SQLite 3 Database (SQLite format 3\\0)';
  if (['jpg', 'jpeg', 'png', 'reg', 'pcap', 'exe', 'pdf', 'zip'].includes(ext)) {
    base.extensionMismatch = true;
    base.mismatchReason = `File has extension ".${ext}", but its binary signature (${magicHex}) is a SQLite 3 database.`;
    anomalies.push(base.mismatchReason);
  }

  if (bytes.length < 100) {
    base.corrupted = true;
    base.errorMessage =
      'CORRUPTED SQLITE DATABASE: Valid "SQLite format 3" signature found, but the 100-byte database header is truncated.';
    return base;
  }

  try {
    let rawPageSize = view.getUint16(16, false);
    if (rawPageSize === 1) rawPageSize = 65536;
    base.pageSize = rawPageSize;

    const writeVer = view.getUint8(18);
    const readVer = view.getUint8(19);
    base.writeReadVersions = `Write: ${writeVer === 2 ? '2 (WAL)' : '1 (Rollback)'} · Read: ${
      readVer === 2 ? '2 (WAL)' : '1 (Rollback)'
    }`;

    base.changeCounter = view.getUint32(24, false);
    const headerPageCount = view.getUint32(28, false);
    const calculatedPages = Math.floor(bytes.length / rawPageSize);
    base.pageCount = headerPageCount || calculatedPages;

    base.freelistPageCount = view.getUint32(36, false);
    if (base.freelistPageCount > 0) {
      anomalies.push(
        `Database contains ${base.freelistPageCount} freelist page(s) — deleted records may exist in unallocated B-Tree pages.`,
      );
    }

    base.schemaCookie = view.getUint32(40, false);
    const encCode = view.getUint32(56, false);
    const encodingMap: Record<number, { label: string; decoder: 'utf-8' | 'utf-16le' | 'utf-16be' }> = {
      1: { label: 'UTF-8 (1)', decoder: 'utf-8' },
      2: { label: 'UTF-16le (2)', decoder: 'utf-16le' },
      3: { label: 'UTF-16be (3)', decoder: 'utf-16be' },
    };
    const encInfo = encodingMap[encCode] ?? { label: 'UTF-8 (Default)', decoder: 'utf-8' };
    base.textEncoding = encInfo.label;

    base.userVersion = view.getUint32(60, false);
    const appIdInt = view.getUint32(68, false);
    const appIdAscii = readAscii(view, 68, 4);
    base.applicationId =
      appIdInt !== 0
        ? `0x${appIdInt.toString(16).toUpperCase()}${appIdAscii ? ` ("${appIdAscii}")` : ''}`
        : '0 (Standard SQLite)';

    const verNum = view.getUint32(96, false);
    if (verNum > 3000000 && verNum < 4000000) {
      const maj = Math.floor(verNum / 1000000);
      const min = Math.floor((verNum % 1000000) / 1000);
      const rel = verNum % 1000;
      base.sqliteVersionString = `${maj}.${min}.${rel} (${verNum})`;
    }

    // 1. Parse sqlite_master (Page 1)
    const visitedMaster = new Set<number>();
    traverseTableBTreePage(
      bytes,
      view,
      1,
      rawPageSize,
      encInfo.decoder,
      visitedMaster,
      (rowId, vals) => {
        const objType = String(vals[0] ?? 'table').toLowerCase() as SqliteSchemaObject['type'];
        const objName = String(vals[1] ?? `object_${rowId}`);
        const tblName = String(vals[2] ?? objName);
        const rootPage = Number(vals[3] ?? 0);
        const sql = String(vals[4] ?? '');

        const columns =
          objType === 'table' && sql ? parseColumnsFromCreateSql(sql) : [];

        schemaObjects.push({
          type: objType,
          name: objName,
          tblName,
          rootPage,
          sql,
          columns,
          rowCount: 0,
          sourceRef: `sqlite_master:rowid=${rowId} (rootpage=${rootPage})`,
        });
      },
      250,
    );

    // 2. For each table in sqlite_master, traverse its B-Tree root page and extract rows
    const tableObjects = schemaObjects.filter(o => o.type === 'table');
    base.tables = tableObjects;

    for (const tbl of tableObjects) {
      const tableRows: SqliteExtractedRow[] = [];
      if (tbl.rootPage > 0 && (tbl.rootPage - 1) * rawPageSize < bytes.length) {
        const visitedTblPages = new Set<number>();
        traverseTableBTreePage(
          bytes,
          view,
          tbl.rootPage,
          rawPageSize,
          encInfo.decoder,
          visitedTblPages,
          (rowId, vals) => {
            const rowObj: Record<string, string | number | null> = {};
            const cols = tbl.columns;

            if (cols.length > 0) {
              for (let c = 0; c < cols.length; c++) {
                const colDef = cols[c];
                let cellVal = vals[c] ?? null;
                // In SQLite, an INTEGER PRIMARY KEY column stores NULL in the record payload and aliases the B-Tree rowId
                if (
                  cellVal === null &&
                  colDef.isPrimaryKey &&
                  colDef.type.toUpperCase().includes('INT')
                ) {
                  cellVal = rowId;
                }
                rowObj[colDef.name] = cellVal;
              }
            } else {
              for (let c = 0; c < vals.length; c++) {
                rowObj[`col_${c + 1}`] = vals[c] ?? null;
              }
            }

            // Check for forensic indicators inside row values
            const concatStr = Object.values(rowObj)
              .filter(v => v !== null)
              .join(' ')
              .toLowerCase();
            let forensicFlag: string | undefined;
            if (
              concatStr.includes('dangerous') ||
              concatStr.includes('stage2') ||
              concatStr.includes('exfil') ||
              concatStr.includes('wevtutil') ||
              concatStr.includes('svchost_helper') ||
              concatStr.includes('\\appdata\\local\\temp')
            ) {
              forensicFlag = `High-interest artifact in ${tbl.name} (rowid=${rowId})`;
            }

            const extractedRow: SqliteExtractedRow = {
              tableName: tbl.name,
              rowId,
              values: rowObj,
              sourceRef: `${tbl.name}:rowid=${rowId}`,
              forensicFlag,
            };
            tableRows.push(extractedRow);
            allRows.push(extractedRow);
            if (forensicFlag) {
              anomalies.push(
                `${forensicFlag}: ${JSON.stringify(rowObj).slice(0, 140)}`,
              );
            }
          },
          300,
        );
      }
      tbl.rowCount = tableRows.length;
      rowsByTable[tbl.name] = tableRows;
    }
  } catch (err) {
    base.corrupted = true;
    base.errorMessage =
      err instanceof Error
        ? `SQLite B-Tree parser caught malformed structure: ${err.message}`
        : 'Malformed SQLite B-Tree page encountered.';
  }

  return base;
}

function FieldRow({
  label,
  value,
  sourceRef,
  mono = false,
}: {
  label: string;
  value: string | number | null | undefined;
  sourceRef?: string;
  mono?: boolean;
}) {
  const present = value !== null && value !== undefined && String(value).trim() !== '';
  return (
    <div className="exif-field-row">
      <div>
        <div className="detail-label" style={{ marginBottom: 3 }}>
          {label}
        </div>
        {present ? (
          <strong className={mono ? 'mono' : ''} style={{ fontSize: 11 }}>
            {value}
          </strong>
        ) : (
          <span className="not-present-badge">Not Present</span>
        )}
      </div>
      {sourceRef && present && (
        <span className="mono muted" style={{ fontSize: 9 }}>
          {sourceRef}
        </span>
      )}
    </div>
  );
}

export function SqliteAnalyzer() {
  const { user, cases, evidence, validations, refresh } = useWorkspace();

  const [mode, setMode] = useState<'evidence' | 'standalone'>('evidence');
  const [caseFilter, setCaseFilter] = useState('all');
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string>('');
  const [analysis, setAnalysis] = useState<ParsedSqliteAnalysis | null>(null);
  const [loading, setLoading] = useState(false);

  // Standalone file state
  const [standaloneFile, setStandaloneFile] = useState<File | null>(null);
  const [standaloneAnalysis, setStandaloneAnalysis] = useState<ParsedSqliteAnalysis | null>(
    null,
  );
  const standaloneInputRef = useRef<HTMLInputElement>(null);

  // Active Table & Row Search State
  const [selectedTableName, setSelectedTableName] = useState<string>('');
  const [rowSearchQuery, setRowSearchQuery] = useState<string>('');

  // Independent Validation Gate state (Section 3, Module 6 & Section 9.2)
  const [independentTool, setIndependentTool] = useState<string>(
    SQLITE_INDEPENDENT_TOOLS[0],
  );
  const [valCheck1, setValCheck1] = useState('');
  const [valCheck2, setValCheck2] = useState('');
  const [valCheck3, setValCheck3] = useState('');
  const [valStatus, setValStatus] = useState<'VERIFIED' | 'MISMATCH' | 'NEEDS REVIEW'>(
    'VERIFIED',
  );
  const [validatorName, setValidatorName] = useState(
    user?.email?.split('@')[0] ?? 'Investigator',
  );
  const [validationNotes, setValidationNotes] = useState('');
  const [savingVal, setSavingVal] = useState(false);

  const filteredEvidence = evidence.filter(
    e => caseFilter === 'all' || e.case_id === caseFilter,
  );
  const selectedEvidence =
    filteredEvidence.find(e => e.id === selectedEvidenceId) ??
    filteredEvidence[0] ??
    null;

  useEffect(() => {
    if (selectedEvidence && selectedEvidence.id !== selectedEvidenceId) {
      setSelectedEvidenceId(selectedEvidence.id);
    }
  }, [selectedEvidence, selectedEvidenceId]);

  const populateDefaultValidationFields = (parsed: ParsedSqliteAnalysis) => {
    const firstTable = parsed.tables[0];
    setSelectedTableName(firstTable?.name ?? '');

    const c1 =
      parsed.pageSize && parsed.tables.length > 0
        ? `Header & Tables: ${parsed.tables.length} tables (${parsed.tables.map(t => `${t.name}:${t.rowCount}`).join(', ')})`
        : `Format: ${parsed.detectedFormat}`;
    const firstRow = parsed.allRows[0];
    const c2 = firstRow
      ? `Record (${firstRow.sourceRef}): ${Object.entries(firstRow.values)
          .slice(0, 3)
          .map(([k, v]) => `${k}=${v}`)
          .join(', ')}`
      : 'Table Records: Not Present';
    const secondTable = parsed.tables[1] ?? parsed.tables[0];
    const secondRow = secondTable ? parsed.rowsByTable[secondTable.name]?.[0] : null;
    const c3 = secondRow
      ? `Record (${secondRow.sourceRef}): ${Object.entries(secondRow.values)
          .slice(0, 3)
          .map(([k, v]) => `${k}=${v}`)
          .join(', ')}`
      : `Schema Cookie: ${parsed.schemaCookie ?? 'Not Present'}`;

    setValCheck1(c1);
    setValCheck2(c2);
    setValCheck3(c3);
  };

  // Parse selected evidence item
  useEffect(() => {
    let cancelled = false;
    async function inspectEvidence() {
      if (!selectedEvidence) {
        setAnalysis(null);
        return;
      }
      setLoading(true);
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
          if (!cancelled) {
            setAnalysis({
              supported: false,
              corrupted: true,
              errorMessage:
                'Original evidence binary not found in local IndexedDB. Switch to Standalone SQLite Inspector or re-upload the database file.',
              detectedFormat: 'Unavailable',
              magicBytesHex: 'N/A',
              extensionName: selectedEvidence.filename,
              extensionMismatch: false,
              sqliteVersionString: null,
              pageSize: null,
              pageCount: null,
              textEncoding: null,
              schemaCookie: null,
              changeCounter: null,
              freelistPageCount: null,
              userVersion: null,
              applicationId: null,
              writeReadVersions: null,
              schemaObjects: [],
              tables: [],
              rowsByTable: {},
              allRows: [],
              anomalies: [],
            });
          }
          return;
        }

        const buffer = await blob.arrayBuffer();
        const parsed = parseSqliteEvidenceBuffer(buffer, selectedEvidence.filename);

        if (!cancelled) {
          setAnalysis(parsed);
          if (parsed.supported && !parsed.corrupted) {
            if (selectedEvidence.processing_status === 'UNPROCESSED') {
              if (markLocalEvidenceProcessed(selectedEvidence.id)) {
                await refresh();
              }
            }
          }
          populateDefaultValidationFields(parsed);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    inspectEvidence();
    return () => {
      cancelled = true;
    };
  }, [selectedEvidence?.id, user]);

  // Parse standalone file
  useEffect(() => {
    let cancelled = false;
    async function inspectStandalone() {
      if (!standaloneFile) {
        setStandaloneAnalysis(null);
        return;
      }
      const buffer = await standaloneFile.arrayBuffer();
      const parsed = parseSqliteEvidenceBuffer(buffer, standaloneFile.name);
      if (!cancelled) {
        setStandaloneAnalysis(parsed);
        populateDefaultValidationFields(parsed);
      }
    }
    inspectStandalone();
    return () => {
      cancelled = true;
    };
  }, [standaloneFile]);

  const handleLoadSampleSqlite = () => {
    const sample = createSampleForensicSqliteFile();
    setMode('standalone');
    setStandaloneFile(sample);
    toast.success(
      'Loaded sample forensic SQLite 3 database (Browser_Forensic_Artifacts.sqlite)!',
    );
  };

  const handleDownloadSampleSqlite = () => {
    const sample = createSampleForensicSqliteFile();
    const url = URL.createObjectURL(sample);
    const a = document.createElement('a');
    a.href = url;
    a.download = sample.name;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(
      `Downloaded ${sample.name} — you can open it in DB Browser for SQLite or sqlite3 CLI!`,
    );
  };

  const activeData = mode === 'evidence' ? analysis : standaloneAnalysis;
  const activeFilename =
    mode === 'evidence'
      ? selectedEvidence?.filename ?? ''
      : standaloneFile?.name ?? '';
  const selectedEvidenceCode =
    mode === 'evidence' && selectedEvidence
      ? getEvidenceCode(selectedEvidence.id, evidence)
      : 'STANDALONE';
  const sqliteValidations = selectedEvidence
    ? validations.filter(v => v.evidence_id === selectedEvidence.id && v.module === 'SQLite')
    : [];

  const activeTableObj =
    activeData?.tables.find(t => t.name === selectedTableName) ??
    activeData?.tables[0] ??
    null;
  const activeTableRows = activeTableObj
    ? activeData?.rowsByTable[activeTableObj.name] ?? []
    : [];

  const filteredRows = activeTableRows.filter(row => {
    const q = rowSearchQuery.trim().toLowerCase();
    if (!q) return true;
    if (String(row.rowId).includes(q)) return true;
    return Object.values(row.values).some(v =>
      String(v ?? '')
        .toLowerCase()
        .includes(q),
    );
  });

  const activeColumnNames =
    activeTableObj && activeTableObj.columns.length > 0
      ? activeTableObj.columns.map(c => c.name)
      : activeTableRows[0]
        ? Object.keys(activeTableRows[0].values)
        : [];

  async function copyText(label: string, text: string) {
    await navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard.`);
  }

  async function handleSqliteValidationSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!activeData) return;
    const confirmed = [valCheck1.trim(), valCheck2.trim(), valCheck3.trim()].filter(
      Boolean,
    );
    if (confirmed.length < 2) {
      toast.error(
        'Please confirm at least 2 SQLite database findings (tables, row counts, or rowid records) to log validation.',
      );
      return;
    }

    setSavingVal(true);
    try {
      const targetEvidence = mode === 'evidence' ? selectedEvidence : null;
      const relatedCase = targetEvidence
        ? cases.find(c => c.id === targetEvidence.case_id)
        : cases[0];
      const evCode = targetEvidence
        ? getEvidenceCode(targetEvidence.id, evidence)
        : 'E-STANDALONE';
      const targetName = targetEvidence
        ? targetEvidence.filename
        : standaloneFile?.name ?? 'database.sqlite';

      const platformSummary = [
        `${activeData.tables.length} tables (${activeData.tables.map(t => `${t.name}:${t.rowCount}`).join(', ')})`,
        `PageSize=${activeData.pageSize ?? 'N/A'}`,
        `TotalRows=${activeData.allRows.length}`,
      ].join(' | ');

      saveValidationRecord({
        case_id: targetEvidence?.case_id ?? relatedCase?.id ?? 'local-case',
        case_number: relatedCase?.case_number ?? 'DB-LOCAL',
        evidence_id: targetEvidence?.id ?? 'standalone-sqlite',
        evidence_code: evCode,
        filename: targetName,
        module: 'SQLite',
        algorithm: 'SQLite B-Tree & RowID Attribution',
        platform_result: platformSummary,
        independent_tool: independentTool,
        independent_result: confirmed.join(' | '),
        status: valStatus,
        validator: validatorName.trim(),
        notes:
          validationNotes.trim() ||
          `Confirmed SQLite schema and rowid records with ${independentTool}.`,
      });

      await refresh();
      setValidationNotes('');
      toast.success(
        `SQLite validation (${valStatus}) recorded for ${evCode} in Validation Log.`,
      );
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : 'Could not save SQLite validation.',
      );
    } finally {
      setSavingVal(false);
    }
  }

  return (
    <div className="hash-analyzer">
      {/* Top Mode Bar */}
      <div className="analyzer-controls">
        <div className="mode-tabs" role="tablist" aria-label="SQLite analyzer mode">
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'evidence'}
            className={`mode-tab ${mode === 'evidence' ? 'active' : ''}`}
            onClick={() => setMode('evidence')}
          >
            <Archive size={15} />
            <span>Inspect Evidence Locker Database</span>
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
            <span>Standalone SQLite Inspector</span>
          </button>
        </div>

        <div className="algo-bar">
          <span className="detail-label" style={{ marginBottom: 0 }}>
            SUPPORTED FORMATS:
          </span>
          <span className="algo-tag">.SQLITE / .SQLITE3</span>
          <span className="algo-tag">.DB / B-Tree v3</span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleLoadSampleSqlite}
          >
            <Sparkles size={13} />
            Load Sample Forensic .SQLITE
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={handleDownloadSampleSqlite}
            title="Download sample .sqlite database to open in DB Browser for SQLite or sqlite3 CLI"
          >
            <Download size={13} />
            Download .SQLITE
          </Button>
        </div>
      </div>

      {/* Selector Bar */}
      {mode === 'evidence' ? (
        evidence.length === 0 ? (
          <Empty
            icon={Database}
            title="No evidence files in your locker yet"
            description="Upload a SQLite database (.sqlite, .db, .sqlite3) in the Evidence Locker, switch to Standalone SQLite Inspector, or click 'Load Sample Forensic .SQLITE' to inspect browser history, downloads, and login tables."
          >
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <Button asChild variant="outline" size="sm">
                <Link to="/evidence">
                  Open Evidence Locker
                  <ArrowUpRight />
                </Link>
              </Button>
              <Button variant="default" size="sm" onClick={() => setMode('standalone')}>
                <Database size={14} />
                Use Standalone SQLite Inspector
              </Button>
              <Button variant="outline" size="sm" onClick={handleLoadSampleSqlite}>
                <Sparkles size={14} />
                Load Sample Forensic .SQLITE
              </Button>
            </div>
          </Empty>
        ) : (
          <section className="analyzer-card">
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
                Select Evidence Item to Inspect
                <select
                  value={selectedEvidence?.id ?? ''}
                  onChange={e => setSelectedEvidenceId(e.target.value)}
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
          </section>
        )
      ) : (
        <section className="analyzer-card">
          <div
            className="upload-zone compact-zone"
            onDragOver={e => e.preventDefault()}
            onDrop={e => {
              e.preventDefault();
              setStandaloneFile(e.dataTransfer.files[0] ?? null);
            }}
          >
            <Upload size={26} />
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <Button
                type="button"
                variant="outline"
                onClick={() => standaloneInputRef.current?.click()}
              >
                Choose .sqlite / .db file from computer
              </Button>
              <Button
                type="button"
                variant="default"
                onClick={handleLoadSampleSqlite}
              >
                <Sparkles size={14} />
                Load Sample Forensic .SQLITE Database
              </Button>
            </div>
            <p>
              {standaloneFile
                ? `${standaloneFile.name} · ${(standaloneFile.size / 1024).toFixed(2)} KB`
                : 'Drop a SQLite 3 database (.sqlite, .db, .sqlite3, Chrome History, SMS/Messages DB) here'}
            </p>
            <input
              ref={standaloneInputRef}
              type="file"
              className="hidden"
              onChange={e => setStandaloneFile(e.target.files?.[0] ?? null)}
            />
          </div>
        </section>
      )}

      {loading && (
        <div className="analyzer-card">
          <p className="mono muted">
            Parsing 100-byte SQLite 3 header, sqlite_master catalog, and B-Tree pages…
          </p>
        </div>
      )}

      {activeData && !loading && (
        <>
          {/* Binary Signature / Spoofed Extension / Unsupported / Corrupted Banner (Section 9.1) */}
          {(!activeData.supported ||
            activeData.corrupted ||
            activeData.extensionMismatch) && (
            <div
              className={`integrity-banner ${
                !activeData.supported || activeData.corrupted ? 'mismatch' : 'review'
              }`}
              style={{ marginTop: 0 }}
            >
              <FileWarning size={22} />
              <div>
                <strong>
                  {!activeData.supported
                    ? 'UNSUPPORTED OR NON-SQLITE FILE FORMAT DETECTED'
                    : activeData.corrupted
                      ? 'CORRUPTED / TRUNCATED SQLITE DATABASE DETECTED'
                      : 'FILE EXTENSION vs. SQLITE MAGIC HEADER MISMATCH'}
                </strong>
                <p>
                  {activeData.errorMessage || activeData.mismatchReason} (Observed Magic Bytes:{' '}
                  <code className="mono">{activeData.magicBytesHex}</code> · Extension:{' '}
                  <code className="mono">{activeData.extensionName}</code>)
                </p>
              </div>
            </div>
          )}

          {activeData.supported && !activeData.corrupted && (
            <>
              <div className="analyzer-grid">
                {/* Left Column: 100-Byte Header + Schema Catalog */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                  {/* Card 1: SQLite 100-Byte Binary Header */}
                  <section className="analyzer-card">
                    <div className="section-title" style={{ paddingTop: 0 }}>
                      <h2>
                        <Database size={17} />1 · SQLite 3 Binary Header (Bytes 0–99)
                      </h2>
                      <span className="algo-tag">
                        {selectedEvidenceCode} · {activeFilename}
                      </span>
                    </div>

                    <div className="exif-fields-grid">
                      <FieldRow
                        label="MAGIC HEADER SIGNATURE"
                        value={activeData.detectedFormat}
                        sourceRef={`Offset 0x00: ${activeData.magicBytesHex}`}
                      />
                      <FieldRow
                        label="EXTENSION vs. SIGNATURE CHECK"
                        value={
                          activeData.extensionMismatch
                            ? `MISMATCH (${activeData.extensionName})`
                            : `VALID (${activeData.extensionName})`
                        }
                        mono
                      />
                      <FieldRow
                        label="SQLITE ENGINE VERSION"
                        value={activeData.sqliteVersionString}
                        sourceRef="Header@0x60"
                        mono
                      />
                      <FieldRow
                        label="PAGE SIZE & PAGE COUNT"
                        value={
                          activeData.pageSize
                            ? `${activeData.pageSize.toLocaleString()} bytes × ${activeData.pageCount} pages (${(
                                (activeData.pageSize * (activeData.pageCount ?? 1)) /
                                1024
                              ).toFixed(1)} KB)`
                            : null
                        }
                        sourceRef="Header@0x10 / 0x1C"
                        mono
                      />
                      <FieldRow
                        label="TEXT ENCODING"
                        value={activeData.textEncoding}
                        sourceRef="Header@0x38"
                        mono
                      />
                      <FieldRow
                        label="JOURNAL / WAL FORMAT"
                        value={activeData.writeReadVersions}
                        sourceRef="Header@0x12-0x13"
                        mono
                      />
                      <FieldRow
                        label="FILE CHANGE COUNTER"
                        value={activeData.changeCounter}
                        sourceRef="Header@0x18"
                        mono
                      />
                      <FieldRow
                        label="SCHEMA COOKIE & USER VERSION"
                        value={`Cookie: ${activeData.schemaCookie ?? 0} · UserVer: ${
                          activeData.userVersion ?? 0
                        }`}
                        sourceRef="Header@0x28 / 0x3C"
                        mono
                      />
                      <FieldRow
                        label="FREELIST PAGES (DELETED SPACE)"
                        value={`${activeData.freelistPageCount ?? 0} page(s)`}
                        sourceRef="Header@0x24"
                        mono
                      />
                      <FieldRow
                        label="APPLICATION ID"
                        value={activeData.applicationId}
                        sourceRef="Header@0x44"
                        mono
                      />
                    </div>
                  </section>

                  {/* Card 2: sqlite_master Schema Catalog */}
                  <section className="analyzer-card">
                    <div className="section-title" style={{ paddingTop: 0 }}>
                      <h2>
                        <FileCode2 size={17} />2 · Schema Catalog (sqlite_master · Page 1)
                      </h2>
                      <span className="count-badge">
                        {activeData.schemaObjects.length} Objects
                      </span>
                    </div>

                    {activeData.schemaObjects.length === 0 ? (
                      <FieldRow
                        label="SQLITE_MASTER SCHEMA OBJECTS"
                        value={null}
                        sourceRef="Page 1"
                      />
                    ) : (
                      <div className="hash-list">
                        {activeData.schemaObjects.map(obj => (
                          <div key={obj.sourceRef} className="hash-item">
                            <div className="hash-item-top">
                              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                <span className="algo-tag">
                                  {obj.type.toUpperCase()}: {obj.name}
                                </span>
                                {obj.type === 'table' && (
                                  <span className="status-badge status-active">
                                    {obj.rowCount} rows
                                  </span>
                                )}
                              </div>
                              <span className="mono muted" style={{ fontSize: 9 }}>
                                {obj.sourceRef}
                              </span>
                            </div>
                            <div
                              className="hash-value"
                              style={{ marginTop: 6, fontSize: 10 }}
                            >
                              {obj.sql || '-- Internal SQLite object'}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </section>
                </div>

                {/* Right Column: Grounded Summary + Validation Gate */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                  {/* Card 3: Evidence-Grounded Forensic Summary */}
                  <section className="analyzer-card">
                    <div className="section-title" style={{ paddingTop: 0 }}>
                      <h2>
                        <Bot size={17} />3 · Evidence-Grounded SQLite Summary
                      </h2>
                      <span className="ai-label">FACT vs. INTERPRETATION</span>
                    </div>

                    <div className="hash-item">
                      <div className="detail-label">
                        OBSERVED FACTS (FROM B-TREE PAGES & ROWID RECORDS)
                      </div>
                      <p style={{ fontSize: 11, lineHeight: 1.65 }}>
                        • <strong>Source Evidence:</strong>{' '}
                        <code className="mono">
                          {selectedEvidenceCode} ({activeFilename})
                        </code>
                        <br />• <strong>Database Parameters:</strong> Page Size:{' '}
                        <strong>{activeData.pageSize} B</strong>, Encoding:{' '}
                        <strong>{activeData.textEncoding}</strong>, Engine:{' '}
                        <strong>{activeData.sqliteVersionString ?? 'SQLite 3'}</strong>.
                        <br />• <strong>Enumerated Tables ({activeData.tables.length}):</strong>{' '}
                        {activeData.tables.length > 0
                          ? activeData.tables
                              .map(
                                t =>
                                  `${t.name} (${t.rowCount} rows, rootpage=${t.rootPage})`,
                              )
                              .join(' · ')
                          : 'Not Present'}
                        .<br />• <strong>Total Extracted Records:</strong>{' '}
                        <strong>{activeData.allRows.length}</strong> rows with exact{' '}
                        <code className="mono">table:rowid</code> attribution.
                      </p>
                    </div>

                    <div className="hash-item">
                      <div className="detail-label">
                        AI COPILOT INTERPRETATION & UNCERTAINTY (UNVERIFIED UNTIL HUMAN CHECK)
                      </div>
                      <p
                        style={{
                          fontSize: 11,
                          lineHeight: 1.65,
                          color: 'var(--muted-foreground)',
                        }}
                      >
                        {activeData.anomalies.length > 0 ? (
                          <>
                            <strong style={{ color: 'var(--amber)' }}>
                              Forensic Indicators Observed:{' '}
                            </strong>
                            {activeData.anomalies.slice(0, 3).join(' | ')} Verify whether
                            Companion <code className="mono">-wal</code> (Write-Ahead Log) or{' '}
                            <code className="mono">-journal</code> files exist in the same
                            directory, as uncommitted transactions may reside outside the main
                            database file.
                          </>
                        ) : (
                          <>
                            All active B-Tree leaf pages parsed cleanly. Remember that deleted
                            SQLite rows may still persist in unallocated cell areas or{' '}
                            <code className="mono">-wal</code> files until a{' '}
                            <code className="mono">VACUUM</code> operation rewrites the database.
                            Independently verify table schemas and row counts using{' '}
                            <code className="mono">sqlite3</code> or DB Browser for SQLite below.
                          </>
                        )}
                      </p>
                    </div>

                    {/* Quick SQLite CLI Reference Commands (Section 13) */}
                    <div className="verify-box" style={{ paddingTop: 10 }}>
                      <div className="detail-label">
                        <Terminal size={12} style={{ display: 'inline', marginRight: 5 }} />
                        SECTION 13 · SQLITE3 INDEPENDENT VALIDATION COMMANDS
                      </div>
                      <div className="cmd-list">
                        {[
                          [
                            'List Tables & Schema',
                            `sqlite3 "${activeFilename}" ".schema"`,
                          ],
                          [
                            'Query Active Table',
                            `sqlite3 -header -column "${activeFilename}" "SELECT rowid, * FROM ${
                              activeTableObj?.name || 'urls'
                            } LIMIT 20;"`,
                          ],
                          [
                            'Row Counts',
                            `sqlite3 "${activeFilename}" "SELECT name, type, rootpage FROM sqlite_master;"`,
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
                  </section>

                  {/* Card 4: Independent SQLite Validation Gate */}
                  <section className="analyzer-card">
                    <div className="section-title" style={{ paddingTop: 0 }}>
                      <h2>
                        <ShieldCheck size={17} />4 · Independent SQLite Validation Gate
                      </h2>
                      <span className="subtle-label">LOG TO 9-COLUMN VALIDATION LOG</span>
                    </div>

                    <form className="form-stack" onSubmit={handleSqliteValidationSubmit}>
                      <div className="form-row">
                        <label className="field-label">
                          Independent Tool Used *
                          <select
                            value={independentTool}
                            onChange={e => setIndependentTool(e.target.value)}
                          >
                            {SQLITE_INDEPENDENT_TOOLS.map(t => (
                              <option key={t} value={t}>
                                {t}
                              </option>
                            ))}
                          </select>
                        </label>

                        <label className="field-label">
                          Validation Outcome *
                          <select
                            value={valStatus}
                            onChange={e =>
                              setValStatus(
                                e.target.value as 'VERIFIED' | 'MISMATCH' | 'NEEDS REVIEW',
                              )
                            }
                          >
                            <option value="VERIFIED">
                              VERIFIED (Tables, row counts & rowids match tool)
                            </option>
                            <option value="MISMATCH">
                              MISMATCH (Discrepancy between platform & tool)
                            </option>
                            <option value="NEEDS REVIEW">
                              NEEDS REVIEW (WAL / unallocated records require review)
                            </option>
                          </select>
                        </label>
                      </div>

                      <label className="field-label">
                        Confirmed Finding #1 (Table List & Row Counts) *
                        <input
                          required
                          value={valCheck1}
                          onChange={e => setValCheck1(e.target.value)}
                          className="mono"
                        />
                      </label>

                      <label className="field-label">
                        Confirmed Finding #2 (Specific Table + RowID Record) *
                        <input
                          required
                          value={valCheck2}
                          onChange={e => setValCheck2(e.target.value)}
                          className="mono"
                        />
                      </label>

                      <label className="field-label">
                        Confirmed Finding #3 (Second Record or Header Parameter)
                        <input
                          value={valCheck3}
                          onChange={e => setValCheck3(e.target.value)}
                          className="mono"
                        />
                      </label>

                      <div className="form-row">
                        <label className="field-label">
                          Validator (Student Name) *
                          <input
                            required
                            value={validatorName}
                            onChange={e => setValidatorName(e.target.value)}
                          />
                        </label>
                        <label className="field-label">
                          Notes / Query Observations
                          <input
                            placeholder="e.g. Verified urls & downloads tables in DB Browser for SQLite"
                            value={validationNotes}
                            onChange={e => setValidationNotes(e.target.value)}
                          />
                        </label>
                      </div>

                      <div className="decision-buttons">
                        <Button
                          type="submit"
                          disabled={savingVal}
                          className={valStatus === 'VERIFIED' ? 'btn-verify' : ''}
                        >
                          {valStatus === 'VERIFIED' ? (
                            <ShieldCheck size={16} />
                          ) : (
                            <ShieldAlert size={16} />
                          )}
                          {savingVal
                            ? 'Saving…'
                            : `Record SQLite ${valStatus} in Validation Log`}
                        </Button>
                        <Button asChild variant="outline" type="button">
                          <Link to="/validation">
                            Open Validation Log
                            <ArrowUpRight size={14} />
                          </Link>
                        </Button>
                      </div>
                    </form>

                    {sqliteValidations.length > 0 && (
                      <div className="verify-box">
                        <div className="detail-label">
                          RECORDED SQLITE VALIDATIONS FOR {selectedEvidenceCode} (
                          {sqliteValidations.length})
                        </div>
                        <div className="hash-list">
                          {sqliteValidations.map(v => (
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
                                  {v.independent_tool}
                                </span>
                                <span className="mono muted" style={{ fontSize: 9 }}>
                                  {v.validator} · {new Date(v.created_at).toLocaleString()}
                                </span>
                              </div>
                              <p className="mono" style={{ fontSize: 9, marginTop: 4 }}>
                                {v.independent_result}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </section>
                </div>
              </div>

              {/* Full-Width Interactive Table Record Browser with Table + RowID Source Attribution */}
              <section className="analyzer-card">
                <div className="section-title" style={{ paddingTop: 0 }}>
                  <h2>
                    <TableIcon size={17} />5 · Interactive Table Record Inspector (Source-Attributed by Table + RowID)
                  </h2>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    {activeTableObj && (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          copyText(
                            `${activeTableObj.name} JSON`,
                            JSON.stringify(activeTableRows, null, 2),
                          )
                        }
                      >
                        <Copy size={12} />
                        Copy Table JSON
                      </Button>
                    )}
                  </div>
                </div>

                {/* Table Selector Pills + Search Input */}
                <div
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    justifyContent: 'space-between',
                    gap: 12,
                    alignItems: 'center',
                  }}
                >
                  <div className="algo-pills" role="tablist" aria-label="Select SQLite table">
                    {activeData.tables.map(tbl => (
                      <button
                        key={tbl.name}
                        type="button"
                        className={`algo-pill ${
                          activeTableObj?.name === tbl.name ? 'active' : ''
                        }`}
                        onClick={() => setSelectedTableName(tbl.name)}
                      >
                        {tbl.name} ({tbl.rowCount})
                      </button>
                    ))}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 260 }}>
                    <Search size={14} className="muted" />
                    <input
                      placeholder={`Filter rows in ${activeTableObj?.name ?? 'table'}…`}
                      value={rowSearchQuery}
                      onChange={e => setRowSearchQuery(e.target.value)}
                    />
                  </div>
                </div>

                {activeTableObj && filteredRows.length > 0 ? (
                  <div className="table-wrap" style={{ maxHeight: 380, overflowY: 'auto' }}>
                    <table>
                      <thead>
                        <tr>
                          <th>SOURCE REFERENCE (TABLE:ROWID)</th>
                          {activeColumnNames.map(col => (
                            <th key={col}>{col.toUpperCase()}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {filteredRows.map(row => (
                          <tr
                            key={row.sourceRef}
                            style={
                              row.forensicFlag
                                ? {
                                    background:
                                      'color-mix(in oklch, var(--amber) 8%, transparent)',
                                  }
                                : undefined
                            }
                          >
                            <td className="mono" style={{ fontSize: 10, whiteSpace: 'nowrap' }}>
                              <span className="algo-tag">{row.sourceRef}</span>
                            </td>
                            {activeColumnNames.map(col => {
                              const cellVal = row.values[col];
                              return (
                                <td
                                  key={col}
                                  className="mono"
                                  style={{
                                    fontSize: 10,
                                    maxWidth: 320,
                                    wordBreak: 'break-all',
                                  }}
                                >
                                  {cellVal === null || cellVal === undefined ? (
                                    <span className="not-present-badge">NULL</span>
                                  ) : (
                                    String(cellVal)
                                  )}
                                </td>
                              );
                            })}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="muted" style={{ fontSize: 11 }}>
                    No records found in this table matching the current filter.
                  </p>
                )}
              </section>
            </>
          )}
        </>
      )}
    </div>
  );
}
