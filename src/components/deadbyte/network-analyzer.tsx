import { useState, useEffect, useMemo, useRef } from 'react';
import {
  useWorkspace,
  Empty,
  getLocalEvidenceBlob,
  getEvidenceCode,
  markLocalEvidenceProcessed,
  saveValidationRecord,
  safeSha256Hex,
} from './workspace';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import {
  Network,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Upload,
  Terminal,
  Copy,
  Check,
  Search,
  Globe,
  Activity,
  CheckCircle2,
  XCircle,
  Clock3,
  FileWarning,
  Layers,
  ArrowRightLeft,
  Eye,
} from 'lucide-react';
import { toast } from 'sonner';

// ============================================================================
// DETERMINISTIC PCAP & PCAPNG BINARY PARSER (MODULE 7 — NWIT 263)
// Pure TypeScript binary packet parser supporting:
// - Classic Libpcap (.pcap) Big-Endian & Little-Endian (microsecond & nanosecond)
// - PCAP Next Generation (.pcapng) Section Header, Interface Description,
//   Enhanced Packet Block (0x00000006), and Simple Packet Block (0x00000003)
// - Link Layers: Ethernet (1), BSD Loopback (0), Raw IP (101), Linux SLL (113/276)
// - Network/Transport: IPv4, IPv6, ARP, TCP, UDP, ICMP, ICMPv6
// - Application Inspection: DNS Queries/Answers, HTTP Requests/Responses, TLS SNI
// ============================================================================

export interface ParsedPacket {
  frameNumber: number;
  fileOffset: number;
  timestampEpochMs: number;
  timestampIso: string;
  relativeTimeSec: number;
  capturedLen: number;
  originalLen: number;
  linkLayer: string;
  srcMac: string | null;
  dstMac: string | null;
  etherTypeHex: string | null;
  networkProtocol: string; // IPv4, IPv6, ARP, Other
  transportProtocol: string; // TCP, UDP, ICMP, ICMPv6, ARP, DNS, HTTP, TLS, Other
  srcIp: string | null;
  dstIp: string | null;
  srcPort: number | null;
  dstPort: number | null;
  ttl: number | null;
  tcpFlags: string | null;
  seqNum: number | null;
  ackNum: number | null;
  info: string;
  dnsQuery: string | null;
  dnsType: string | null;
  dnsIsResponse: boolean;
  dnsAnswers: string[];
  httpMethod: string | null;
  httpHost: string | null;
  httpUri: string | null;
  httpUserAgent: string | null;
  httpStatus: string | null;
  tlsSni: string | null;
  suspiciousReason: string | null;
  rawPreviewBytes: Uint8Array;
}

export interface IpConversation {
  id: string;
  endpointA: string;
  endpointB: string;
  packetsAtoB: number;
  packetsBtoA: number;
  totalPackets: number;
  bytesAtoB: number;
  bytesBtoA: number;
  totalBytes: number;
  protocols: string[];
  firstFrame: number;
  lastFrame: number;
}

export interface DnsArtifact {
  frameNumber: number;
  timestampIso: string;
  srcIp: string;
  dstIp: string;
  queryName: string;
  queryType: string;
  isResponse: boolean;
  answers: string[];
}

export interface HttpTlsArtifact {
  frameNumber: number;
  timestampIso: string;
  type: 'HTTP Request' | 'HTTP Response' | 'TLS ClientHello (SNI)';
  srcEndpoint: string;
  dstEndpoint: string;
  hostOrSni: string | null;
  methodOrStatus: string | null;
  uri: string | null;
  userAgent: string | null;
}

export interface PcapMetadataResult {
  fileName: string;
  fileSize: number;
  sha256: string;
  claimedExtension: string;
  magicHex: string;
  detectedFormat: 'PCAP (Libpcap)' | 'PCAPNG (Next Generation)' | 'Unknown / Unsupported';
  endianness: 'Little-Endian' | 'Big-Endian' | 'N/A';
  timestampResolution: 'Microseconds (us)' | 'Nanoseconds (ns)' | 'N/A';
  versionString: string;
  snapLen: number | null;
  linkTypeCode: number | null;
  linkTypeName: string;
  isValidCapture: boolean;
  isSpoofed: boolean;
  spoofReason: string;
  totalPackets: number;
  totalCapturedBytes: number;
  totalWireBytes: number;
  captureStartIso: string | null;
  captureEndIso: string | null;
  captureDurationSec: number | null;
  protocolCounts: Record<string, number>;
  packets: ParsedPacket[];
  conversations: IpConversation[];
  dnsArtifacts: DnsArtifact[];
  httpTlsArtifacts: HttpTlsArtifact[];
  suspiciousIndicators: { frameNumber: number; category: string; detail: string }[];
  parseNotes: string[];
}

async function computeSha256(buffer: ArrayBuffer): Promise<string> {
  return safeSha256Hex(buffer);
}

function bytesToHex(bytes: Uint8Array, maxLen = 16): string {
  return Array.from(bytes.slice(0, maxLen))
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

function formatMac(bytes: Uint8Array, offset: number): string {
  if (offset + 6 > bytes.length) return 'Not Present';
  const parts: string[] = [];
  for (let i = 0; i < 6; i++) {
    parts.push((bytes[offset + i] ?? 0).toString(16).padStart(2, '0').toUpperCase());
  }
  return parts.join(':');
}

function formatIpv4(bytes: Uint8Array, offset: number): string {
  if (offset + 4 > bytes.length) return '0.0.0.0';
  return `${bytes[offset] ?? 0}.${bytes[offset + 1] ?? 0}.${bytes[offset + 2] ?? 0}.${bytes[offset + 3] ?? 0}`;
}

function formatIpv6(bytes: Uint8Array, offset: number): string {
  if (offset + 16 > bytes.length) return '::';
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    const val = ((bytes[offset + i] ?? 0) << 8) | (bytes[offset + i + 1] ?? 0);
    groups.push(val.toString(16));
  }
  return groups.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
}

function getLinkTypeName(code: number): string {
  switch (code) {
    case 0:
      return 'BSD Loopback (DLT_NULL / 0)';
    case 1:
      return 'Ethernet (DLT_EN10MB / 1)';
    case 101:
      return 'Raw IP (DLT_RAW / 101)';
    case 105:
      return 'IEEE 802.11 Wireless LAN (105)';
    case 113:
      return 'Linux Cooked Capture v1 (DLT_LINUX_SLL / 113)';
    case 276:
      return 'Linux Cooked Capture v2 (DLT_LINUX_SLL2 / 276)';
    default:
      return `Link-Layer Type ${code}`;
  }
}

function getDnsTypeName(qtype: number): string {
  switch (qtype) {
    case 1:
      return 'A';
    case 2:
      return 'NS';
    case 5:
      return 'CNAME';
    case 6:
      return 'SOA';
    case 12:
      return 'PTR';
    case 15:
      return 'MX';
    case 16:
      return 'TXT';
    case 28:
      return 'AAAA';
    case 33:
      return 'SRV';
    case 65:
      return 'HTTPS';
    case 255:
      return 'ANY';
    default:
      return `TYPE${qtype}`;
  }
}

function readDnsName(
  dnsPayload: Uint8Array,
  startOffset: number,
  maxJumps = 8
): { name: string; nextOffset: number } | null {
  if (startOffset >= dnsPayload.length) return null;
  const labels: string[] = [];
  let offset = startOffset;
  let nextOffset = -1;
  let jumps = 0;

  while (offset < dnsPayload.length && jumps <= maxJumps) {
    const len = dnsPayload[offset] ?? 0;
    if (len === 0) {
      if (nextOffset === -1) nextOffset = offset + 1;
      break;
    }
    // DNS compression pointer (top 2 bits = 11)
    if ((len & 0xc0) === 0xc0) {
      if (offset + 1 >= dnsPayload.length) return null;
      const ptr = ((len & 0x3f) << 8) | (dnsPayload[offset + 1] ?? 0);
      if (nextOffset === -1) nextOffset = offset + 2;
      offset = ptr;
      jumps++;
      continue;
    }
    if ((len & 0xc0) !== 0) return null; // invalid label length
    if (offset + 1 + len > dnsPayload.length) return null;
    let label = '';
    for (let i = 0; i < len; i++) {
      const ch = dnsPayload[offset + 1 + i] ?? 0;
      label += ch >= 32 && ch <= 126 ? String.fromCharCode(ch) : '.';
    }
    labels.push(label);
    offset += 1 + len;
  }

  if (nextOffset === -1) nextOffset = offset;
  return { name: labels.join('.') || '<root>', nextOffset };
}

function parseDnsPayload(payload: Uint8Array): {
  isResponse: boolean;
  queryName: string | null;
  queryType: string | null;
  answers: string[];
} | null {
  if (payload.length < 12) return null;
  const flags = ((payload[2] ?? 0) << 8) | (payload[3] ?? 0);
  const isResponse = (flags & 0x8000) !== 0;
  const qdCount = ((payload[4] ?? 0) << 8) | (payload[5] ?? 0);
  const anCount = ((payload[6] ?? 0) << 8) | (payload[7] ?? 0);
  if (qdCount === 0 || qdCount > 32) return null;

  let offset = 12;
  let queryName: string | null = null;
  let queryType: string | null = null;

  for (let q = 0; q < qdCount; q++) {
    const res = readDnsName(payload, offset);
    if (!res) return null;
    offset = res.nextOffset;
    if (offset + 4 > payload.length) return null;
    const qtype = ((payload[offset] ?? 0) << 8) | (payload[offset + 1] ?? 0);
    if (q === 0) {
      queryName = res.name;
      queryType = getDnsTypeName(qtype);
    }
    offset += 4;
  }

  const answers: string[] = [];
  if (isResponse && anCount > 0 && anCount <= 64) {
    for (let a = 0; a < anCount; a++) {
      const nameRes = readDnsName(payload, offset);
      if (!nameRes) break;
      offset = nameRes.nextOffset;
      if (offset + 10 > payload.length) break;
      const rtype = ((payload[offset] ?? 0) << 8) | (payload[offset + 1] ?? 0);
      const rdLength = ((payload[offset + 8] ?? 0) << 8) | (payload[offset + 9] ?? 0);
      offset += 10;
      if (offset + rdLength > payload.length) break;

      if (rtype === 1 && rdLength === 4) {
        answers.push(formatIpv4(payload, offset));
      } else if (rtype === 28 && rdLength === 16) {
        answers.push(formatIpv6(payload, offset));
      } else if (rtype === 5 || rtype === 12 || rtype === 2) {
        const cnameRes = readDnsName(payload, offset);
        if (cnameRes?.name) answers.push(cnameRes.name);
      }
      offset += rdLength;
    }
  }

  return { isResponse, queryName, queryType, answers };
}

function parseHttpPayload(payload: Uint8Array): {
  method: string | null;
  uri: string | null;
  host: string | null;
  userAgent: string | null;
  status: string | null;
} | null {
  if (payload.length < 10) return null;
  const maxScan = Math.min(payload.length, 2048);
  let ascii = '';
  for (let i = 0; i < maxScan; i++) {
    const b = payload[i] ?? 0;
    ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : b === 10 || b === 13 ? String.fromCharCode(b) : '';
  }

  const firstLineEnd = ascii.indexOf('\r\n');
  const firstLine = (firstLineEnd !== -1 ? ascii.slice(0, firstLineEnd) : ascii.split('\n')[0] ?? '').trim();

  const reqMatch = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP\/1\.[01]/i.exec(firstLine);
  const resMatch = /^HTTP\/1\.[01]\s+(\d{3}\s+[^\r\n]*)/i.exec(firstLine);

  if (!reqMatch && !resMatch) return null;

  const hostMatch = /\nHost:\s*([^\r\n]+)/i.exec(ascii);
  const uaMatch = /\nUser-Agent:\s*([^\r\n]+)/i.exec(ascii);

  return {
    method: reqMatch ? (reqMatch[1] ?? '').toUpperCase() : null,
    uri: reqMatch ? (reqMatch[2] ?? null) : null,
    host: hostMatch ? (hostMatch[1] ?? '').trim() : null,
    userAgent: uaMatch ? (uaMatch[1] ?? '').trim() : null,
    status: resMatch ? `HTTP ${resMatch[1]?.trim() ?? ''}` : null,
  };
}

function parseTlsClientHelloSni(payload: Uint8Array): string | null {
  // TLS Handshake record: ContentType = 0x16 (22), Version = 0x0301..0x0303, HandshakeType = 0x01 (ClientHello)
  if (payload.length < 43) return null;
  if (payload[0] !== 0x16 || payload[1] !== 0x03) return null;
  const recordLen = ((payload[3] ?? 0) << 8) | (payload[4] ?? 0);
  if (recordLen + 5 > payload.length && payload.length < 50) return null;
  if (payload[5] !== 0x01) return null; // HandshakeType 1 = ClientHello

  // Skip Record Header (5) + Handshake Header (4) + Client Version (2) + Random (32) = 43
  let offset = 43;
  if (offset >= payload.length) return null;

  // Session ID
  const sessionIdLen = payload[offset] ?? 0;
  offset += 1 + sessionIdLen;
  if (offset + 2 > payload.length) return null;

  // Cipher Suites
  const cipherSuitesLen = ((payload[offset] ?? 0) << 8) | (payload[offset + 1] ?? 0);
  offset += 2 + cipherSuitesLen;
  if (offset + 1 > payload.length) return null;

  // Compression Methods
  const compMethodsLen = payload[offset] ?? 0;
  offset += 1 + compMethodsLen;
  if (offset + 2 > payload.length) return null;

  // Extensions Length
  const extensionsLen = ((payload[offset] ?? 0) << 8) | (payload[offset + 1] ?? 0);
  offset += 2;
  const endExtensions = Math.min(payload.length, offset + extensionsLen);

  while (offset + 4 <= endExtensions) {
    const extType = ((payload[offset] ?? 0) << 8) | (payload[offset + 1] ?? 0);
    const extLen = ((payload[offset + 2] ?? 0) << 8) | (payload[offset + 3] ?? 0);
    offset += 4;
    if (offset + extLen > endExtensions) break;

    // Extension 0x0000 = server_name (SNI)
    if (extType === 0x0000 && extLen >= 5) {
      const nameType = payload[offset + 2] ?? 0;
      const nameLen = ((payload[offset + 3] ?? 0) << 8) | (payload[offset + 4] ?? 0);
      if (nameType === 0 && offset + 5 + nameLen <= endExtensions) {
        let sni = '';
        for (let i = 0; i < nameLen; i++) {
          const ch = payload[offset + 5 + i] ?? 0;
          if (ch >= 32 && ch <= 126) sni += String.fromCharCode(ch);
        }
        if (sni) return sni;
      }
    }
    offset += extLen;
  }

  return null;
}

function decodePacketBytes(
  pktBytes: Uint8Array,
  frameNumber: number,
  fileOffset: number,
  timestampEpochMs: number,
  firstTimestampMs: number,
  originalLen: number,
  linkTypeCode: number
): ParsedPacket {
  let srcMac: string | null = null;
  let dstMac: string | null = null;
  let etherType = 0;
  let etherTypeHex: string | null = null;
  let netOffset = 0;
  let linkLayer = getLinkTypeName(linkTypeCode);

  if (linkTypeCode === 1 && pktBytes.length >= 14) {
    // Standard Ethernet (14 bytes)
    dstMac = formatMac(pktBytes, 0);
    srcMac = formatMac(pktBytes, 6);
    etherType = ((pktBytes[12] ?? 0) << 8) | (pktBytes[13] ?? 0);
    netOffset = 14;
    // Handle 802.1Q VLAN Tag (0x8100)
    if (etherType === 0x8100 && pktBytes.length >= 18) {
      etherType = ((pktBytes[16] ?? 0) << 8) | (pktBytes[17] ?? 0);
      netOffset = 18;
    }
    etherTypeHex = `0x${etherType.toString(16).padStart(4, '0').toUpperCase()}`;
  } else if (linkTypeCode === 101 && pktBytes.length >= 1) {
    // Raw IP
    const version = (pktBytes[0] ?? 0) >> 4;
    etherType = version === 6 ? 0x86dd : 0x0800;
    etherTypeHex = `0x${etherType.toString(16).padStart(4, '0').toUpperCase()}`;
    netOffset = 0;
  } else if (linkTypeCode === 0 && pktBytes.length >= 4) {
    // BSD Loopback
    const family = pktBytes[0] === 2 || pktBytes[3] === 2 ? 2 : 24;
    etherType = family === 2 ? 0x0800 : 0x86dd;
    etherTypeHex = `0x${etherType.toString(16).padStart(4, '0').toUpperCase()}`;
    netOffset = 4;
  } else if (linkTypeCode === 113 && pktBytes.length >= 16) {
    // Linux SLL v1
    etherType = ((pktBytes[14] ?? 0) << 8) | (pktBytes[15] ?? 0);
    etherTypeHex = `0x${etherType.toString(16).padStart(4, '0').toUpperCase()}`;
    netOffset = 16;
  } else if (linkTypeCode === 276 && pktBytes.length >= 20) {
    // Linux SLL v2
    etherType = ((pktBytes[0] ?? 0) << 8) | (pktBytes[1] ?? 0);
    etherTypeHex = `0x${etherType.toString(16).padStart(4, '0').toUpperCase()}`;
    netOffset = 20;
  }

  let networkProtocol = 'Other';
  let transportProtocol = 'Other';
  let srcIp: string | null = null;
  let dstIp: string | null = null;
  let srcPort: number | null = null;
  let dstPort: number | null = null;
  let ttl: number | null = null;
  let tcpFlags: string | null = null;
  let seqNum: number | null = null;
  let ackNum: number | null = null;
  let info = `Raw Frame (${pktBytes.length} bytes)`;
  let dnsQuery: string | null = null;
  let dnsType: string | null = null;
  let dnsIsResponse = false;
  let dnsAnswers: string[] = [];
  let httpMethod: string | null = null;
  let httpHost: string | null = null;
  let httpUri: string | null = null;
  let httpUserAgent: string | null = null;
  let httpStatus: string | null = null;
  let tlsSni: string | null = null;
  let suspiciousReason: string | null = null;

  // Check ARP (0x0806)
  if (etherType === 0x0806 && pktBytes.length >= netOffset + 28) {
    networkProtocol = 'ARP';
    transportProtocol = 'ARP';
    const oper = ((pktBytes[netOffset + 6] ?? 0) << 8) | (pktBytes[netOffset + 7] ?? 0);
    const senderMac = formatMac(pktBytes, netOffset + 8);
    const senderIp = formatIpv4(pktBytes, netOffset + 14);
    const targetIp = formatIpv4(pktBytes, netOffset + 24);
    srcIp = senderIp;
    dstIp = targetIp;
    info =
      oper === 1
        ? `ARP Request: Who has ${targetIp}? Tell ${senderIp} (${senderMac})`
        : oper === 2
        ? `ARP Reply: ${senderIp} is at ${senderMac}`
        : `ARP Operation ${oper}: ${senderIp} -> ${targetIp}`;
  } else if (etherType === 0x0800 && pktBytes.length >= netOffset + 20) {
    // IPv4 (0x0800)
    networkProtocol = 'IPv4';
    const verIhl = pktBytes[netOffset] ?? 0x45;
    const ihl = (verIhl & 0x0f) * 4;
    ttl = pktBytes[netOffset + 8] ?? null;
    const ipProto = pktBytes[netOffset + 9] ?? 0;
    srcIp = formatIpv4(pktBytes, netOffset + 12);
    dstIp = formatIpv4(pktBytes, netOffset + 16);
    const transOffset = netOffset + Math.max(20, ihl);

    const decoded = decodeTransportLayer(pktBytes, transOffset, ipProto, srcIp, dstIp);
    transportProtocol = decoded.transportProtocol;
    srcPort = decoded.srcPort;
    dstPort = decoded.dstPort;
    tcpFlags = decoded.tcpFlags;
    seqNum = decoded.seqNum;
    ackNum = decoded.ackNum;
    info = decoded.info;
    dnsQuery = decoded.dnsQuery;
    dnsType = decoded.dnsType;
    dnsIsResponse = decoded.dnsIsResponse;
    dnsAnswers = decoded.dnsAnswers;
    httpMethod = decoded.httpMethod;
    httpHost = decoded.httpHost;
    httpUri = decoded.httpUri;
    httpUserAgent = decoded.httpUserAgent;
    httpStatus = decoded.httpStatus;
    tlsSni = decoded.tlsSni;
    suspiciousReason = decoded.suspiciousReason;
  } else if (etherType === 0x86dd && pktBytes.length >= netOffset + 40) {
    // IPv6 (0x86DD)
    networkProtocol = 'IPv6';
    const nextHeader = pktBytes[netOffset + 6] ?? 0;
    ttl = pktBytes[netOffset + 7] ?? null;
    srcIp = formatIpv6(pktBytes, netOffset + 8);
    dstIp = formatIpv6(pktBytes, netOffset + 24);
    const transOffset = netOffset + 40;

    const decoded = decodeTransportLayer(pktBytes, transOffset, nextHeader, srcIp, dstIp);
    transportProtocol = decoded.transportProtocol;
    srcPort = decoded.srcPort;
    dstPort = decoded.dstPort;
    tcpFlags = decoded.tcpFlags;
    seqNum = decoded.seqNum;
    ackNum = decoded.ackNum;
    info = decoded.info;
    dnsQuery = decoded.dnsQuery;
    dnsType = decoded.dnsType;
    dnsIsResponse = decoded.dnsIsResponse;
    dnsAnswers = decoded.dnsAnswers;
    httpMethod = decoded.httpMethod;
    httpHost = decoded.httpHost;
    httpUri = decoded.httpUri;
    httpUserAgent = decoded.httpUserAgent;
    httpStatus = decoded.httpStatus;
    tlsSni = decoded.tlsSni;
    suspiciousReason = decoded.suspiciousReason;
  }

  const validTime =
    Number.isFinite(timestampEpochMs) && timestampEpochMs > 0 && timestampEpochMs < 4102444800000;
  const timestampIso = validTime ? new Date(timestampEpochMs).toISOString() : 'Not Present';
  const relativeTimeSec =
    validTime && firstTimestampMs > 0 ? Math.max(0, (timestampEpochMs - firstTimestampMs) / 1000) : 0;

  return {
    frameNumber,
    fileOffset,
    timestampEpochMs: validTime ? timestampEpochMs : 0,
    timestampIso,
    relativeTimeSec,
    capturedLen: pktBytes.length,
    originalLen,
    linkLayer,
    srcMac,
    dstMac,
    etherTypeHex,
    networkProtocol,
    transportProtocol,
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    ttl,
    tcpFlags,
    seqNum,
    ackNum,
    info,
    dnsQuery,
    dnsType,
    dnsIsResponse,
    dnsAnswers,
    httpMethod,
    httpHost,
    httpUri,
    httpUserAgent,
    httpStatus,
    tlsSni,
    suspiciousReason,
    rawPreviewBytes: pktBytes.slice(0, 96),
  };
}

function decodeTransportLayer(
  pktBytes: Uint8Array,
  transOffset: number,
  ipProto: number,
  srcIp: string,
  dstIp: string
): {
  transportProtocol: string;
  srcPort: number | null;
  dstPort: number | null;
  tcpFlags: string | null;
  seqNum: number | null;
  ackNum: number | null;
  info: string;
  dnsQuery: string | null;
  dnsType: string | null;
  dnsIsResponse: boolean;
  dnsAnswers: string[];
  httpMethod: string | null;
  httpHost: string | null;
  httpUri: string | null;
  httpUserAgent: string | null;
  httpStatus: string | null;
  tlsSni: string | null;
  suspiciousReason: string | null;
} {
  let transportProtocol = `IP-Proto-${ipProto}`;
  let srcPort: number | null = null;
  let dstPort: number | null = null;
  let tcpFlags: string | null = null;
  let seqNum: number | null = null;
  let ackNum: number | null = null;
  let info = `${srcIp} -> ${dstIp}`;
  let dnsQuery: string | null = null;
  let dnsType: string | null = null;
  let dnsIsResponse = false;
  let dnsAnswers: string[] = [];
  let httpMethod: string | null = null;
  let httpHost: string | null = null;
  let httpUri: string | null = null;
  let httpUserAgent: string | null = null;
  let httpStatus: string | null = null;
  let tlsSni: string | null = null;
  let suspiciousReason: string | null = null;

  const dv = new DataView(pktBytes.buffer, pktBytes.byteOffset, pktBytes.byteLength);

  if (ipProto === 6 && pktBytes.length >= transOffset + 20) {
    // TCP
    transportProtocol = 'TCP';
    srcPort = dv.getUint16(transOffset, false);
    dstPort = dv.getUint16(transOffset + 2, false);
    seqNum = dv.getUint32(transOffset + 4, false);
    ackNum = dv.getUint32(transOffset + 8, false);
    const dataOffset = ((pktBytes[transOffset + 12] ?? 0x50) >> 4) * 4;
    const flagsByte = pktBytes[transOffset + 13] ?? 0;

    const flagNames: string[] = [];
    if (flagsByte & 0x02) flagNames.push('SYN');
    if (flagsByte & 0x10) flagNames.push('ACK');
    if (flagsByte & 0x01) flagNames.push('FIN');
    if (flagsByte & 0x04) flagNames.push('RST');
    if (flagsByte & 0x08) flagNames.push('PSH');
    if (flagsByte & 0x20) flagNames.push('URG');
    tcpFlags = flagNames.join(', ') || 'NONE';

    const payloadOffset = transOffset + Math.max(20, dataOffset);
    const payload = payloadOffset < pktBytes.length ? pktBytes.subarray(payloadOffset) : new Uint8Array(0);

    info = `${srcPort} -> ${dstPort} [${tcpFlags}] Seq=${seqNum} Len=${payload.length}`;

    // Check suspicious ports or flags
    if (flagsByte === 0x00) {
      suspiciousReason = 'TCP NULL Scan packet detected (no TCP flags set).';
    } else if ((flagsByte & 0x29) === 0x29) {
      suspiciousReason = 'TCP XMAS Scan packet detected (FIN+PSH+URG flags set).';
    } else if (
      dstPort === 4444 ||
      srcPort === 4444 ||
      dstPort === 1337 ||
      srcPort === 1337 ||
      dstPort === 31337 ||
      srcPort === 31337
    ) {
      suspiciousReason = `Connection on common C2 / backdoor port (${dstPort === 4444 || dstPort === 1337 || dstPort === 31337 ? dstPort : srcPort}).`;
    }

    if (payload.length > 0) {
      const http = parseHttpPayload(payload);
      if (http) {
        transportProtocol = 'HTTP';
        httpMethod = http.method;
        httpUri = http.uri;
        httpHost = http.host;
        httpUserAgent = http.userAgent;
        httpStatus = http.status;
        if (httpMethod) {
          info = `HTTP ${httpMethod} ${httpHost ? `http://${httpHost}` : ''}${httpUri ?? '/'} ${httpUserAgent ? `(UA: ${httpUserAgent.slice(0, 36)})` : ''}`;
        } else if (httpStatus) {
          info = `${httpStatus}`;
        }
      } else {
        const sni = parseTlsClientHelloSni(payload);
        if (sni) {
          transportProtocol = 'TLS';
          tlsSni = sni;
          info = `TLS ClientHello (SNI: ${sni}) [${srcPort} -> ${dstPort}]`;
        } else if (srcPort === 443 || dstPort === 443) {
          if (payload[0] === 0x16 || payload[0] === 0x17) {
            transportProtocol = 'TLS';
          }
        }
      }
    }
  } else if (ipProto === 17 && pktBytes.length >= transOffset + 8) {
    // UDP
    transportProtocol = 'UDP';
    srcPort = dv.getUint16(transOffset, false);
    dstPort = dv.getUint16(transOffset + 2, false);
    const udpLen = dv.getUint16(transOffset + 4, false);
    const payload = pktBytes.subarray(transOffset + 8);
    info = `${srcPort} -> ${dstPort} Len=${ Math.max(0, udpLen - 8) }`;

    if (
      (srcPort === 53 || dstPort === 53 || srcPort === 5353 || dstPort === 5353 || srcPort === 5355 || dstPort === 5355) &&
      payload.length >= 12
    ) {
      const dns = parseDnsPayload(payload);
      if (dns && dns.queryName) {
        transportProtocol = 'DNS';
        dnsQuery = dns.queryName;
        dnsType = dns.queryType;
        dnsIsResponse = dns.isResponse;
        dnsAnswers = dns.answers;
        info = dns.isResponse
          ? `DNS Response ${dns.queryType ?? ''} ${dns.queryName} -> ${dns.answers.length ? dns.answers.join(', ') : 'No Answer'}`
          : `DNS Standard Query ${dns.queryType ?? ''} ${dns.queryName}`;
      }
    }
  } else if (ipProto === 1 && pktBytes.length >= transOffset + 4) {
    // ICMP
    transportProtocol = 'ICMP';
    const icmpType = pktBytes[transOffset] ?? 0;
    const icmpCode = pktBytes[transOffset + 1] ?? 0;
    info =
      icmpType === 8
        ? `ICMP Echo (Ping) Request (type=8, code=${icmpCode})`
        : icmpType === 0
        ? `ICMP Echo (Ping) Reply (type=0, code=${icmpCode})`
        : icmpType === 3
        ? `ICMP Destination Unreachable (type=3, code=${icmpCode})`
        : icmpType === 11
        ? `ICMP Time Exceeded (type=11, code=${icmpCode})`
        : `ICMP Type ${icmpType} Code ${icmpCode}`;
  } else if (ipProto === 58 && pktBytes.length >= transOffset + 4) {
    // ICMPv6
    transportProtocol = 'ICMPv6';
    const icmpType = pktBytes[transOffset] ?? 0;
    info =
      icmpType === 128
        ? 'ICMPv6 Echo Request'
        : icmpType === 129
        ? 'ICMPv6 Echo Reply'
        : icmpType === 135
        ? 'ICMPv6 Neighbor Solicitation'
        : icmpType === 136
        ? 'ICMPv6 Neighbor Advertisement'
        : `ICMPv6 Type ${icmpType}`;
  }

  return {
    transportProtocol,
    srcPort,
    dstPort,
    tcpFlags,
    seqNum,
    ackNum,
    info,
    dnsQuery,
    dnsType,
    dnsIsResponse,
    dnsAnswers,
    httpMethod,
    httpHost,
    httpUri,
    httpUserAgent,
    httpStatus,
    tlsSni,
    suspiciousReason,
  };
}

export async function parsePcapForensics(file: File): Promise<PcapMetadataResult> {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const sha256 = await computeSha256(buffer);

  const extParts = file.name.toLowerCase().split('.');
  const claimedExtension = extParts.length > 1 ? `.${extParts[extParts.length - 1]}` : '(no extension)';
  const magicHex = bytesToHex(bytes, 16);

  const parseNotes: string[] = [];

  if (bytes.length < 24) {
    return {
      fileName: file.name,
      fileSize: file.size,
      sha256,
      claimedExtension,
      magicHex,
      detectedFormat: 'Unknown / Unsupported',
      endianness: 'N/A',
      timestampResolution: 'N/A',
      versionString: 'Not Present',
      snapLen: null,
      linkTypeCode: null,
      linkTypeName: 'Not Present',
      isValidCapture: false,
      isSpoofed: true,
      spoofReason: 'File is smaller than the minimum 24-byte Libpcap global header.',
      totalPackets: 0,
      totalCapturedBytes: 0,
      totalWireBytes: 0,
      captureStartIso: null,
      captureEndIso: null,
      captureDurationSec: null,
      protocolCounts: {},
      packets: [],
      conversations: [],
      dnsArtifacts: [],
      httpTlsArtifacts: [],
      suspiciousIndicators: [],
      parseNotes: ['File is too small (< 24 bytes) to be a valid PCAP or PCAPNG capture.'],
    };
  }

  const magicU32BE = view.getUint32(0, false);
  const isPcapLEMicro = magicU32BE === 0xd4c3b2a1;
  const isPcapBEMicro = magicU32BE === 0xa1b2c3d4;
  const isPcapLENano = magicU32BE === 0x4d3cb2a1;
  const isPcapBENano = magicU32BE === 0xa1b23c4d;
  const isPcapNg = magicU32BE === 0x0a0d0d0a;

  // Detect non-PCAP disguised formats for spoofing check
  let disguisedFormat: string | null = null;
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) disguisedFormat = 'Windows PE Executable (MZ)';
  else if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47)
    disguisedFormat = 'PNG Image';
  else if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) disguisedFormat = 'JPEG Image';
  else if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46)
    disguisedFormat = 'PDF Document';
  else if (bytes[0] === 0x53 && bytes[1] === 0x51 && bytes[2] === 0x4c && bytes[3] === 0x69)
    disguisedFormat = 'SQLite 3 Database';

  if (!isPcapLEMicro && !isPcapBEMicro && !isPcapLENano && !isPcapBENano && !isPcapNg) {
    return {
      fileName: file.name,
      fileSize: file.size,
      sha256,
      claimedExtension,
      magicHex,
      detectedFormat: 'Unknown / Unsupported',
      endianness: 'N/A',
      timestampResolution: 'N/A',
      versionString: 'Not Present',
      snapLen: null,
      linkTypeCode: null,
      linkTypeName: 'Not Present',
      isValidCapture: false,
      isSpoofed: true,
      spoofReason: disguisedFormat
        ? `Extension claims ${claimedExtension}, but binary header matches ${disguisedFormat} (${magicHex}).`
        : `Invalid capture header (${magicHex}). Expected Libpcap (D4 C3 B2 A1 / A1 B2 C3 D4) or PCAPNG (0A 0D 0D 0A).`,
      totalPackets: 0,
      totalCapturedBytes: 0,
      totalWireBytes: 0,
      captureStartIso: null,
      captureEndIso: null,
      captureDurationSec: null,
      protocolCounts: {},
      packets: [],
      conversations: [],
      dnsArtifacts: [],
      httpTlsArtifacts: [],
      suspiciousIndicators: [],
      parseNotes: ['Binary header does not match Libpcap (.pcap) or PCAPNG (.pcapng) specifications.'],
    };
  }

  const expectedExts = ['.pcap', '.pcapng', '.cap', '.dmp'];
  const isSpoofed = !expectedExts.includes(claimedExtension);
  const spoofReason = isSpoofed
    ? `File has extension "${claimedExtension}", but binary signature is a valid ${isPcapNg ? 'PCAPNG' : 'Libpcap PCAP'} packet capture.`
    : 'Magic signature matches expected packet capture extension.';

  const packets: ParsedPacket[] = [];
  let totalCapturedBytes = 0;
  let totalWireBytes = 0;
  let firstTimestampMs = 0;
  let lastTimestampMs = 0;
  let versionString = '2.4';
  let snapLen: number | null = null;
  let linkTypeCode: number | null = 1;
  let endianness: 'Little-Endian' | 'Big-Endian' = 'Little-Endian';
  let timestampResolution: 'Microseconds (us)' | 'Nanoseconds (ns)' = 'Microseconds (us)';

  const MAX_PARSED_PACKETS = 5000;

  if (!isPcapNg) {
    // Classic Libpcap (.pcap)
    const littleEndian = isPcapLEMicro || isPcapLENano;
    const isNano = isPcapLENano || isPcapBENano;
    endianness = littleEndian ? 'Little-Endian' : 'Big-Endian';
    timestampResolution = isNano ? 'Nanoseconds (ns)' : 'Microseconds (us)';

    const vMajor = view.getUint16(4, littleEndian);
    const vMinor = view.getUint16(6, littleEndian);
    versionString = `Libpcap v${vMajor}.${vMinor}`;
    snapLen = view.getUint32(16, littleEndian);
    linkTypeCode = view.getUint32(20, littleEndian);

    let offset = 24;
    let frameNum = 0;

    while (offset + 16 <= bytes.length && frameNum < MAX_PARSED_PACKETS) {
      const pktOffset = offset;
      const tsSec = view.getUint32(offset, littleEndian);
      const tsSub = view.getUint32(offset + 4, littleEndian);
      const inclLen = view.getUint32(offset + 8, littleEndian);
      const origLen = view.getUint32(offset + 12, littleEndian);
      offset += 16;

      if (inclLen > bytes.length - offset || inclLen > 262144) {
        parseNotes.push(`Truncated or oversized packet record at byte offset 0x${pktOffset.toString(16).toUpperCase()}.`);
        break;
      }

      frameNum++;
      const tsMs = tsSec * 1000 + (isNano ? tsSub / 1_000_000 : tsSub / 1_000);
      if (frameNum === 1 && tsMs > 0) firstTimestampMs = tsMs;
      if (tsMs > 0) lastTimestampMs = tsMs;

      const pktBytes = bytes.subarray(offset, offset + inclLen);
      totalCapturedBytes += inclLen;
      totalWireBytes += origLen;

      packets.push(
        decodePacketBytes(pktBytes, frameNum, pktOffset, tsMs, firstTimestampMs, origLen, linkTypeCode)
      );

      offset += inclLen;
    }

    parseNotes.push(
      `Parsed classic Libpcap (${endianness}, ${timestampResolution}) header: ${versionString}, LinkType=${getLinkTypeName(linkTypeCode)}, SnapLen=${snapLen} bytes.`
    );
  } else {
    // PCAPNG (.pcapng)
    let offset = 0;
    let littleEndian = true;
    let frameNum = 0;
    const interfaceLinkTypes: number[] = [];
    const interfaceTsResol: number[] = []; // multiplier to convert raw 64-bit timestamp to milliseconds

    while (offset + 8 <= bytes.length && frameNum < MAX_PARSED_PACKETS) {
      const blockOffset = offset;
      let blockType = view.getUint32(offset, littleEndian);

      if (blockType === 0x0a0d0d0a && offset + 12 <= bytes.length) {
        // Section Header Block (SHB) determines endianness via byte-order magic at +8
        const bom = view.getUint32(offset + 8, true);
        littleEndian = bom === 0x1a2b3c4d;
        endianness = littleEndian ? 'Little-Endian' : 'Big-Endian';
        blockType = view.getUint32(offset, littleEndian);
      }

      const blockTotalLength = view.getUint32(offset + 4, littleEndian);
      if (blockTotalLength < 12 || offset + blockTotalLength > bytes.length) {
        parseNotes.push(`Stopped at PCAPNG block offset 0x${blockOffset.toString(16).toUpperCase()} (length=${blockTotalLength}).`);
        break;
      }

      if (blockType === 0x0a0d0d0a && offset + 16 <= bytes.length) {
        const vMajor = view.getUint16(offset + 12, littleEndian);
        const vMinor = view.getUint16(offset + 14, littleEndian);
        versionString = `PCAPNG v${vMajor}.${vMinor}`;
      } else if (blockType === 0x00000001 && offset + 16 <= bytes.length) {
        // Interface Description Block (IDB)
        const idbLinkType = view.getUint16(offset + 8, littleEndian);
        const idbSnapLen = view.getUint32(offset + 12, littleEndian);
        interfaceLinkTypes.push(idbLinkType);
        interfaceTsResol.push(0.001); // default 10^-6 sec (microseconds) -> * 0.001 for ms
        if (interfaceLinkTypes.length === 1) {
          linkTypeCode = idbLinkType;
          snapLen = idbSnapLen;
        }
      } else if (blockType === 0x00000006 && offset + 32 <= bytes.length) {
        // Enhanced Packet Block (EPB)
        const interfaceId = view.getUint32(offset + 8, littleEndian);
        const tsHigh = view.getUint32(offset + 12, littleEndian);
        const tsLow = view.getUint32(offset + 16, littleEndian);
        const capturedLen = view.getUint32(offset + 20, littleEndian);
        const origLen = view.getUint32(offset + 24, littleEndian);

        const pktDataOffset = offset + 28;
        if (pktDataOffset + capturedLen <= offset + blockTotalLength - 4) {
          frameNum++;
          const rawTs = tsHigh * 4294967296 + tsLow;
          const mult = interfaceTsResol[interfaceId] ?? 0.001;
          const tsMs = rawTs * mult;
          if (frameNum === 1 && tsMs > 0) firstTimestampMs = tsMs;
          if (tsMs > 0) lastTimestampMs = tsMs;

          const pktLinkType = interfaceLinkTypes[interfaceId] ?? linkTypeCode ?? 1;
          const pktBytes = bytes.subarray(pktDataOffset, pktDataOffset + capturedLen);
          totalCapturedBytes += capturedLen;
          totalWireBytes += origLen;

          packets.push(
            decodePacketBytes(pktBytes, frameNum, blockOffset, tsMs, firstTimestampMs, origLen, pktLinkType)
          );
        }
      } else if (blockType === 0x00000003 && offset + 16 <= bytes.length) {
        // Simple Packet Block (SPB)
        const origLen = view.getUint32(offset + 8, littleEndian);
        const capturedLen = Math.min(origLen, blockTotalLength - 16);
        const pktDataOffset = offset + 12;
        if (capturedLen > 0 && pktDataOffset + capturedLen <= offset + blockTotalLength - 4) {
          frameNum++;
          const pktBytes = bytes.subarray(pktDataOffset, pktDataOffset + capturedLen);
          totalCapturedBytes += capturedLen;
          totalWireBytes += origLen;

          packets.push(
            decodePacketBytes(pktBytes, frameNum, blockOffset, 0, firstTimestampMs, origLen, linkTypeCode ?? 1)
          );
        }
      }

      // Advance by 4-byte aligned blockTotalLength
      const alignedLen = (blockTotalLength + 3) & ~3;
      offset += alignedLen;
    }

    parseNotes.push(
      `Parsed PCAPNG (${endianness}) capture: ${versionString}, Interfaces=${interfaceLinkTypes.length || 1}, Primary LinkType=${getLinkTypeName(linkTypeCode ?? 1)}.`
    );
  }

  // Aggregate Protocol Counts, IP Conversations, DNS Artifacts, HTTP/TLS Artifacts, and Suspicious Indicators
  const protocolCounts: Record<string, number> = {};
  const convMap = new Map<string, IpConversation>();
  const dnsArtifacts: DnsArtifact[] = [];
  const httpTlsArtifacts: HttpTlsArtifact[] = [];
  const suspiciousIndicators: { frameNumber: number; category: string; detail: string }[] = [];
  const synTracker = new Map<string, Set<number>>();

  for (const pkt of packets) {
    const protoKey = pkt.transportProtocol !== 'Other' ? pkt.transportProtocol : pkt.networkProtocol;
    protocolCounts[protoKey] = (protocolCounts[protoKey] ?? 0) + 1;

    if (pkt.srcIp && pkt.dstIp) {
      const aFirst = pkt.srcIp.localeCompare(pkt.dstIp) <= 0;
      const epA = aFirst ? pkt.srcIp : pkt.dstIp;
      const epB = aFirst ? pkt.dstIp : pkt.srcIp;
      const convKey = `${epA}<->${epB}`;
      let conv = convMap.get(convKey);
      if (!conv) {
        conv = {
          id: convKey,
          endpointA: epA,
          endpointB: epB,
          packetsAtoB: 0,
          packetsBtoA: 0,
          totalPackets: 0,
          bytesAtoB: 0,
          bytesBtoA: 0,
          totalBytes: 0,
          protocols: [],
          firstFrame: pkt.frameNumber,
          lastFrame: pkt.frameNumber,
        };
        convMap.set(convKey, conv);
      }
      if (aFirst) {
        conv.packetsAtoB++;
        conv.bytesAtoB += pkt.capturedLen;
      } else {
        conv.packetsBtoA++;
        conv.bytesBtoA += pkt.capturedLen;
      }
      conv.totalPackets++;
      conv.totalBytes += pkt.capturedLen;
      conv.lastFrame = pkt.frameNumber;
      if (!conv.protocols.includes(protoKey)) {
        conv.protocols.push(protoKey);
      }

      // Track distinct SYN destination ports per source->target pair to flag port scanning
      if (pkt.tcpFlags === 'SYN' && pkt.dstPort !== null) {
        const pairKey = `${pkt.srcIp}->${pkt.dstIp}`;
        let portSet = synTracker.get(pairKey);
        if (!portSet) {
          portSet = new Set<number>();
          synTracker.set(pairKey, portSet);
        }
        portSet.add(pkt.dstPort);
      }
    }

    if (pkt.dnsQuery) {
      dnsArtifacts.push({
        frameNumber: pkt.frameNumber,
        timestampIso: pkt.timestampIso,
        srcIp: pkt.srcIp ?? 'Not Present',
        dstIp: pkt.dstIp ?? 'Not Present',
        queryName: pkt.dnsQuery,
        queryType: pkt.dnsType ?? 'A',
        isResponse: pkt.dnsIsResponse,
        answers: pkt.dnsAnswers,
      });
    }

    if (pkt.httpMethod || pkt.httpStatus) {
      httpTlsArtifacts.push({
        frameNumber: pkt.frameNumber,
        timestampIso: pkt.timestampIso,
        type: pkt.httpMethod ? 'HTTP Request' : 'HTTP Response',
        srcEndpoint: `${pkt.srcIp ?? '?'}:${pkt.srcPort ?? '?'}`,
        dstEndpoint: `${pkt.dstIp ?? '?'}:${pkt.dstPort ?? '?'}`,
        hostOrSni: pkt.httpHost,
        methodOrStatus: pkt.httpMethod ?? pkt.httpStatus,
        uri: pkt.httpUri,
        userAgent: pkt.httpUserAgent,
      });
    } else if (pkt.tlsSni) {
      httpTlsArtifacts.push({
        frameNumber: pkt.frameNumber,
        timestampIso: pkt.timestampIso,
        type: 'TLS ClientHello (SNI)',
        srcEndpoint: `${pkt.srcIp ?? '?'}:${pkt.srcPort ?? '?'}`,
        dstEndpoint: `${pkt.dstIp ?? '?'}:${pkt.dstPort ?? '?'}`,
        hostOrSni: pkt.tlsSni,
        methodOrStatus: 'ClientHello',
        uri: null,
        userAgent: null,
      });
    }

    if (pkt.suspiciousReason) {
      suspiciousIndicators.push({
        frameNumber: pkt.frameNumber,
        category: 'Packet Anomaly',
        detail: pkt.suspiciousReason,
      });
    }
  }

  for (const [pairKey, portSet] of synTracker.entries()) {
    if (portSet.size >= 4) {
      suspiciousIndicators.push({
        frameNumber: 1,
        category: 'Potential TCP SYN Port Scan',
        detail: `${pairKey} sent TCP SYN packets to ${portSet.size} distinct destination ports (${Array.from(portSet).slice(0, 8).join(', ')}).`,
      });
    }
  }

  const conversations = Array.from(convMap.values()).sort((a, b) => b.totalBytes - a.totalBytes);

  const captureStartIso =
    firstTimestampMs > 0 && firstTimestampMs < 4102444800000 ? new Date(firstTimestampMs).toISOString() : null;
  const captureEndIso =
    lastTimestampMs > 0 && lastTimestampMs < 4102444800000 ? new Date(lastTimestampMs).toISOString() : null;
  const captureDurationSec =
    firstTimestampMs > 0 && lastTimestampMs >= firstTimestampMs
      ? Number(((lastTimestampMs - firstTimestampMs) / 1000).toFixed(3))
      : null;

  return {
    fileName: file.name,
    fileSize: file.size,
    sha256,
    claimedExtension,
    magicHex,
    detectedFormat: isPcapNg ? 'PCAPNG (Next Generation)' : 'PCAP (Libpcap)',
    endianness,
    timestampResolution,
    versionString,
    snapLen,
    linkTypeCode,
    linkTypeName: getLinkTypeName(linkTypeCode ?? 1),
    isValidCapture: true,
    isSpoofed,
    spoofReason,
    totalPackets: packets.length,
    totalCapturedBytes,
    totalWireBytes,
    captureStartIso,
    captureEndIso,
    captureDurationSec,
    protocolCounts,
    packets,
    conversations,
    dnsArtifacts,
    httpTlsArtifacts,
    suspiciousIndicators,
    parseNotes,
  };
}

function NotPresentBadge({ label = 'Not Present' }: { label?: string }) {
  return <span className="not-present-badge">{label}</span>;
}

function formatHexDump(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.subarray(i, i + 16);
    const hexPart = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ')
      .padEnd(47, ' ');
    const asciiPart = Array.from(slice)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    lines.push(`${i.toString(16).padStart(4, '0').toUpperCase()}  ${hexPart}  |${asciiPart}|`);
  }
  return lines.join('\n');
}

export function NetworkAnalyzer() {
  const { user, cases, evidence, validations, refresh } = useWorkspace();
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string>('');
  const [result, setResult] = useState<PcapMetadataResult | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedFrame, setSelectedFrame] = useState<number>(1);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Validation Gate state
  const [fieldPreset, setFieldPreset] = useState<string>('Total Packet Count');
  const [externalToolName, setExternalToolName] = useState<string>('Wireshark / tshark');
  const [externalCommand, setExternalCommand] = useState<string>('');
  const [externalValue, setExternalValue] = useState<string>('');
  const [validatorName, setValidatorName] = useState<string>('Local Investigator');
  const [investigatorNotes, setInvestigatorNotes] = useState<string>('');
  const [savingValidation, setSavingValidation] = useState(false);

  const selectedEvidence = useMemo(
    () => evidence.find((e) => e.id === selectedEvidenceId) ?? null,
    [evidence, selectedEvidenceId]
  );

  // Auto-select first network capture evidence item if available
  useEffect(() => {
    if (!selectedEvidenceId && evidence.length > 0) {
      const pcapItem = evidence.find((e) => /\.(pcap|pcapng|cap|dmp)$/i.test(e.filename));
      if (pcapItem) {
        setSelectedEvidenceId(pcapItem.id);
      }
    }
  }, [evidence, selectedEvidenceId]);

  useEffect(() => {
    if (selectedEvidence) {
      void analyzeEvidenceItem(selectedEvidence.id);
    }
  }, [selectedEvidenceId]);

  async function analyzeEvidenceItem(evidenceId: string) {
    const ev = evidence.find((e) => e.id === evidenceId);
    if (!ev) return;
    setAnalyzing(true);
    try {
      let fileObj: File | null = null;
      const localBlob = await getLocalEvidenceBlob(ev.storage_path);
      if (localBlob) {
        fileObj = new File([localBlob], ev.filename, {
          type: ev.file_type || 'application/vnd.tcpdump.pcap',
        });
      } else if (user && ev.storage_path) {
        const { data, error } = await supabase.storage.from('evidence').download(ev.storage_path);
        if (!error && data) {
          fileObj = new File([data], ev.filename, { type: ev.file_type || 'application/vnd.tcpdump.pcap' });
        }
      }
      if (!fileObj) {
        toast.error('Original capture file binary not found in local IndexedDB locker. Please upload the .pcap file below.');
        setAnalyzing(false);
        return;
      }
      const parsed = await parsePcapForensics(fileObj);
      setResult(parsed);
      setSelectedFrame(parsed.packets[0]?.frameNumber ?? 1);
      setExternalCommand(`tshark -r "${fileObj.name}" -q -z io,phs`);
      if (markLocalEvidenceProcessed(ev.id)) {
        await refresh();
      }
      toast.success(`Parsed ${parsed.totalPackets} packets from ${fileObj.name}`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to parse packet capture.');
    } finally {
      setAnalyzing(false);
    }
  }

  async function processUploadedFile(file: File) {
    setAnalyzing(true);
    try {
      const parsed = await parsePcapForensics(file);
      setResult(parsed);
      setSelectedFrame(parsed.packets[0]?.frameNumber ?? 1);
      setExternalCommand(`tshark -r "${file.name}" -q -z io,phs`);
      toast.success(`Analyzed ${file.name} (${parsed.totalPackets} packets extracted)`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Error parsing capture file.');
    } finally {
      setAnalyzing(false);
    }
  }

  async function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    await processUploadedFile(file);
    e.target.value = '';
  }

  const deadbyteToolValue = useMemo(() => {
    if (!result) return '';
    switch (fieldPreset) {
      case 'Total Packet Count':
        return `${result.totalPackets} packets (${result.totalCapturedBytes.toLocaleString()} bytes captured)`;
      case 'Capture SHA-256':
        return result.sha256;
      case 'Capture Format & Link Layer':
        return `${result.detectedFormat} | ${result.linkTypeName} (${result.magicHex.slice(0, 11)})`;
      case 'Top IP Conversation': {
        const top = result.conversations[0];
        return top
          ? `${top.endpointA} <-> ${top.endpointB} (${top.totalPackets} packets, ${top.totalBytes} bytes)`
          : 'Not Present';
      }
      case 'First DNS Query': {
        const dns = result.dnsArtifacts[0];
        return dns ? `Frame #${dns.frameNumber}: ${dns.queryName} (${dns.queryType})` : 'Not Present';
      }
      case 'First HTTP / TLS Host': {
        const http = result.httpTlsArtifacts[0];
        return http
          ? `Frame #${http.frameNumber}: ${http.type} — ${http.hostOrSni ?? http.uri ?? 'Not Present'}`
          : 'Not Present';
      }
      default:
        return `${result.totalPackets} packets`;
    }
  }, [result, fieldPreset]);

  const filteredPackets = useMemo(() => {
    if (!result) return [];
    const q = searchQuery.trim().toLowerCase();
    return result.packets.filter((p) => {
      if (protocolFilter !== 'ALL') {
        const proto = p.transportProtocol !== 'Other' ? p.transportProtocol : p.networkProtocol;
        if (proto !== protocolFilter && p.networkProtocol !== protocolFilter) return false;
      }
      if (!q) return true;
      return (
        `#${p.frameNumber}`.includes(q) ||
        (p.srcIp ?? '').toLowerCase().includes(q) ||
        (p.dstIp ?? '').toLowerCase().includes(q) ||
        String(p.srcPort ?? '').includes(q) ||
        String(p.dstPort ?? '').includes(q) ||
        p.transportProtocol.toLowerCase().includes(q) ||
        p.info.toLowerCase().includes(q) ||
        (p.dnsQuery ?? '').toLowerCase().includes(q) ||
        (p.httpHost ?? '').toLowerCase().includes(q) ||
        (p.tlsSni ?? '').toLowerCase().includes(q)
      );
    });
  }, [result, protocolFilter, searchQuery]);

  const activePacket = useMemo(() => {
    if (!result) return null;
    return result.packets.find((p) => p.frameNumber === selectedFrame) ?? filteredPackets[0] ?? null;
  }, [result, selectedFrame, filteredPackets]);

  function copyCommand(id: string, text: string) {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    toast.success('Validation command copied to clipboard.');
    setTimeout(() => setCopiedCmd(null), 1800);
  }

  async function submitValidation(status: 'VERIFIED' | 'MISMATCH' | 'NEEDS REVIEW') {
    if (!result) return;
    if (!externalValue.trim()) {
      toast.error('Please enter the External Tool Output from Wireshark or tshark before logging validation.');
      return;
    }
    setSavingValidation(true);
    try {
      const evDisplayId = selectedEvidence
        ? getEvidenceCode(selectedEvidence.id, evidence)
        : 'E-PCAP';
      const caseObj = selectedEvidence ? cases.find((c) => c.id === selectedEvidence.case_id) : cases[0];

      saveValidationRecord({
        case_id: selectedEvidence?.case_id ?? caseObj?.id ?? 'local-case',
        case_number: caseObj?.case_number ?? 'DB-LOCAL',
        evidence_id: selectedEvidence?.id ?? 'standalone-pcap',
        evidence_code: evDisplayId,
        filename: result.fileName,
        module: 'PCAP',
        algorithm: fieldPreset,
        platform_result: deadbyteToolValue,
        independent_tool: `${externalToolName.trim() || 'Wireshark / tshark'} (${externalCommand.trim() || `tshark -r "${result.fileName}"`})`,
        independent_result: externalValue.trim(),
        status,
        validator: validatorName.trim() || user?.email || caseObj?.investigator || 'Local Investigator',
        notes: investigatorNotes.trim() || `Validated ${fieldPreset} on ${result.fileName}.`,
      });

      await refresh();
      toast.success(`Logged ${status} entry for ${evDisplayId} to the 9-Column Validation Log.`);
      setExternalValue('');
      setInvestigatorNotes('');
    } finally {
      setSavingValidation(false);
    }
  }

  const evidenceValidations = useMemo(
    () =>
      validations.filter(
        (v) =>
          v.module === 'PCAP' &&
          ((selectedEvidence && v.evidence_id === selectedEvidence.id) ||
            (result && v.filename === result.fileName))
      ),
    [validations, selectedEvidence, result]
  );

  const targetFilename = result?.fileName ?? selectedEvidence?.filename ?? 'evidence_capture.pcap';

  return (
    <div className="hash-analyzer">
      {/* Top Evidence Selector & Direct PCAP File Upload Bar */}
      <div className="analyzer-controls">
        <div className="control-group" style={{ flex: 1 }}>
          <label htmlFor="pcap-evidence-select">SELECT EVIDENCE ITEM FROM LOCKER</label>
          <select
            id="pcap-evidence-select"
            value={selectedEvidenceId}
            onChange={(e) => setSelectedEvidenceId(e.target.value)}
          >
            <option value="">— Select preserved evidence or upload a .pcap/.pcapng file —</option>
            {evidence.map((ev) => {
              const c = cases.find((cs) => cs.id === ev.case_id);
              const evCode = getEvidenceCode(ev.id, evidence);
              return (
                <option key={ev.id} value={ev.id}>
                  [{evCode}] {ev.filename} ({c ? c.case_number : 'Case'}) · {ev.validation_status}
                </option>
              );
            })}
          </select>
        </div>

        <div className="control-actions" style={{ display: 'flex', gap: 8, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng,.cap,.dmp,application/vnd.tcpdump.pcap,application/octet-stream"
            className="hidden"
            onChange={handleFileUpload}
          />
          <Button type="button" variant="default" size="sm" onClick={() => fileInputRef.current?.click()}>
            <Upload size={14} /> Upload .PCAP / .PCAPNG File
          </Button>
        </div>
      </div>

      {analyzing && (
        <div className="analyzer-card" style={{ textAlign: 'center', padding: '2rem' }}>
          <Network className="spin" size={28} />
          <p style={{ marginTop: 8 }}>Parsing binary capture headers, Ethernet/IP frames, and application payloads…</p>
        </div>
      )}

      {!analyzing && !result && (
        <section className="analyzer-card">
          <div
            className="upload-zone compact-zone"
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              const dropped = e.dataTransfer.files[0];
              if (dropped) void processUploadedFile(dropped);
            }}
          >
            <Network size={28} />
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <Button type="button" variant="default" onClick={() => fileInputRef.current?.click()}>
                <Upload size={14} /> Choose .pcap / .pcapng file from computer
              </Button>
            </div>
            <p>
              Drop a Wireshark / tcpdump packet capture (<code>.pcap</code>, <code>.pcapng</code>, <code>.cap</code>) here or select an item from your Evidence Locker above to inspect packets, IP conversations, DNS queries, and HTTP/TLS traffic.
            </p>
          </div>
        </section>
      )}

      {!analyzing && result && (
        <>
          {/* Spoofing / Invalid Capture Banner */}
          {(result.isSpoofed || !result.isValidCapture) && (
            <div
              className="analyzer-card"
              style={{
                borderColor: 'rgba(239, 68, 68, 0.55)',
                background: 'rgba(239, 68, 68, 0.08)',
                marginBottom: 16,
              }}
            >
              <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                <FileWarning size={22} style={{ color: '#f87171', flexShrink: 0, marginTop: 2 }} />
                <div>
                  <strong style={{ color: '#fca5a5', display: 'block', marginBottom: 4 }}>
                    {result.isValidCapture
                      ? 'EXTENSION SPOOFING ALERT — BINARY SIGNATURE MISMATCH'
                      : 'INVALID PACKET CAPTURE HEADER'}
                  </strong>
                  <p style={{ margin: 0, fontSize: '0.88rem', opacity: 0.92 }}>{result.spoofReason}</p>
                </div>
              </div>
            </div>
          )}

          {/* Row 1: Capture Header Metadata & Protocol Distribution */}
          <div className="analyzer-grid">
            <section className="analyzer-card">
              <div className="section-title">
                <h2>
                  <Layers size={17} /> Capture Container & Header Metadata
                </h2>
                <span className={`status-badge ${result.isValidCapture ? 'status-active' : ''}`}>
                  {result.detectedFormat}
                </span>
              </div>

              <div className="exif-fields-grid">
                <div className="exif-field-row">
                  <span className="exif-label">Evidence File</span>
                  <span className="mono">{result.fileName}</span>
                </div>
                <div className="exif-field-row">
                  <span className="exif-label">File Size</span>
                  <span className="mono">{result.fileSize.toLocaleString()} bytes</span>
                </div>
                <div className="exif-field-row">
                  <span className="exif-label">SHA-256 Digest</span>
                  <span className="mono" style={{ wordBreak: 'break-all', fontSize: '0.78rem' }}>
                    {result.sha256}
                  </span>
                </div>
                <div className="exif-field-row">
                  <span className="exif-label">Magic Signature (0x00)</span>
                  <span className="mono">{result.magicHex}</span>
                </div>
                <div className="exif-field-row">
                  <span className="exif-label">Format & Endianness</span>
                  <span>
                    {result.detectedFormat} · <span className="mono">{result.endianness}</span>
                  </span>
                </div>
                <div className="exif-field-row">
                  <span className="exif-label">Version & Resolution</span>
                  <span className="mono">
                    {result.versionString} ({result.timestampResolution})
                  </span>
                </div>
                <div className="exif-field-row">
                  <span className="exif-label">Link-Layer Encapsulation</span>
                  <span className="mono">{result.linkTypeName}</span>
                </div>
                <div className="exif-field-row">
                  <span className="exif-label">Snapshot Length (SnapLen)</span>
                  <span>{result.snapLen !== null ? <span className="mono">{result.snapLen} bytes</span> : <NotPresentBadge />}</span>
                </div>
                <div className="exif-field-row">
                  <span className="exif-label">Total Packets Extracted</span>
                  <span className="mono">
                    <strong>{result.totalPackets.toLocaleString()}</strong> frames ({result.totalCapturedBytes.toLocaleString()} bytes captured)
                  </span>
                </div>
                <div className="exif-field-row">
                  <span className="exif-label">First Packet UTC</span>
                  <span>{result.captureStartIso ? <span className="mono">{result.captureStartIso}</span> : <NotPresentBadge />}</span>
                </div>
                <div className="exif-field-row">
                  <span className="exif-label">Last Packet UTC</span>
                  <span>{result.captureEndIso ? <span className="mono">{result.captureEndIso}</span> : <NotPresentBadge />}</span>
                </div>
                <div className="exif-field-row">
                  <span className="exif-label">Capture Duration</span>
                  <span>
                    {result.captureDurationSec !== null ? (
                      <span className="mono">{result.captureDurationSec} seconds</span>
                    ) : (
                      <NotPresentBadge />
                    )}
                  </span>
                </div>
              </div>
            </section>

            {/* Protocol Hierarchy & Forensic Indicators */}
            <section className="analyzer-card">
              <div className="section-title">
                <h2>
                  <Activity size={17} /> Protocol Hierarchy & Forensic Indicators
                </h2>
                <span className="subtle-label">OBSERVED FACTS</span>
              </div>

              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: '0.76rem', opacity: 0.72, marginBottom: 8, letterSpacing: '0.05em' }}>
                  OBSERVED PROTOCOL DISTRIBUTION
                </div>
                {Object.keys(result.protocolCounts).length > 0 ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {Object.entries(result.protocolCounts).map(([proto, count]) => (
                      <button
                        key={proto}
                        type="button"
                        onClick={() => setProtocolFilter(protocolFilter === proto ? 'ALL' : proto)}
                        className="status-badge"
                        style={{
                          cursor: 'pointer',
                          border: protocolFilter === proto ? '1px solid #a855f7' : undefined,
                          background: protocolFilter === proto ? 'rgba(168, 85, 247, 0.2)' : undefined,
                        }}
                      >
                        {proto}: <strong style={{ marginLeft: 4 }}>{count}</strong>
                      </button>
                    ))}
                    {protocolFilter !== 'ALL' && (
                      <button
                        type="button"
                        onClick={() => setProtocolFilter('ALL')}
                        className="status-badge"
                        style={{ cursor: 'pointer' }}
                      >
                        Reset Filter (ALL)
                      </button>
                    )}
                  </div>
                ) : (
                  <NotPresentBadge label="No Protocols Decoded" />
                )}
              </div>

              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: '0.76rem', opacity: 0.72, marginBottom: 8, letterSpacing: '0.05em' }}>
                  AUTOMATED ANOMALY & INDICATOR CHECKS
                </div>
                {result.suspiciousIndicators.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {result.suspiciousIndicators.slice(0, 6).map((ind, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: '8px 10px',
                          borderRadius: 8,
                          background: 'rgba(245, 158, 11, 0.1)',
                          border: '1px solid rgba(245, 158, 11, 0.35)',
                          fontSize: '0.83rem',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                          <strong style={{ color: '#fbbf24' }}>{ind.category}</strong>
                          <span className="mono" style={{ fontSize: '0.76rem' }}>
                            Frame #{ind.frameNumber}
                          </span>
                        </div>
                        <div style={{ opacity: 0.9 }}>{ind.detail}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="exif-field-row">
                    <span className="exif-label">Suspicious Indicators</span>
                    <NotPresentBadge label="None Flagged" />
                  </div>
                )}
              </div>

              <div
                style={{
                  padding: '10px 12px',
                  borderRadius: 8,
                  background: 'rgba(56, 189, 248, 0.07)',
                  border: '1px solid rgba(56, 189, 248, 0.25)',
                  fontSize: '0.8rem',
                }}
              >
                <strong style={{ display: 'block', marginBottom: 3, color: '#7dd3fc' }}>
                  Forensic Scope Note (Observed Facts vs. Interpretation)
                </strong>
                Packet headers, IP addresses, ports, DNS queries, and HTTP/TLS headers are deterministic facts read from{' '}
                <span className="mono">{result.fileName}</span>. Attributing network traffic to a specific human user requires correlating host artifacts (Registry, browser history, or authentication logs).
              </div>
            </section>
          </div>

          {/* Row 2: Top Talkers / IP Conversations */}
          <section className="analyzer-card" style={{ marginTop: 16 }}>
            <div className="section-title">
              <h2>
                <ArrowRightLeft size={17} /> IP Conversations (Top Talkers)
                <span className="count-badge">{result.conversations.length}</span>
              </h2>
              <span className="subtle-label">ATTRIBUTED BY FRAME RANGE</span>
            </div>

            {result.conversations.length > 0 ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>ENDPOINT A</th>
                      <th>ENDPOINT B</th>
                      <th>PACKETS (A → B / B → A)</th>
                      <th>TOTAL PACKETS</th>
                      <th>TOTAL BYTES</th>
                      <th>PROTOCOLS</th>
                      <th>FRAME REFERENCE</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.conversations.slice(0, 25).map((conv) => (
                      <tr key={conv.id}>
                        <td className="mono">{conv.endpointA}</td>
                        <td className="mono">{conv.endpointB}</td>
                        <td className="mono">
                          {conv.packetsAtoB} → / ← {conv.packetsBtoA}
                        </td>
                        <td className="mono">
                          <strong>{conv.totalPackets}</strong>
                        </td>
                        <td className="mono">{conv.totalBytes.toLocaleString()} B</td>
                        <td>
                          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                            {conv.protocols.map((pr) => (
                              <span key={pr} className="status-badge" style={{ fontSize: '0.7rem' }}>
                                {pr}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="mono" style={{ fontSize: '0.78rem' }}>
                          Frame #{conv.firstFrame} – #{conv.lastFrame}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div style={{ padding: '12px 0' }}>
                <NotPresentBadge label="Not Present — No IPv4/IPv6 conversations found in capture" />
              </div>
            )}
          </section>

          {/* Row 3: Extracted DNS Queries & HTTP / TLS SNI Application Artifacts */}
          <div className="analyzer-grid" style={{ marginTop: 16 }}>
            <section className="analyzer-card">
              <div className="section-title">
                <h2>
                  <Globe size={17} /> Extracted DNS Queries & Answers
                  <span className="count-badge">{result.dnsArtifacts.length}</span>
                </h2>
                <span className="subtle-label">PORT 53 / mDNS / LLMNR</span>
              </div>

              {result.dnsArtifacts.length > 0 ? (
                <div className="table-wrap" style={{ maxHeight: 280, overflowY: 'auto' }}>
                  <table>
                    <thead>
                      <tr>
                        <th>FRAME</th>
                        <th>TYPE</th>
                        <th>DOMAIN QUERY</th>
                        <th>RESOLVED ANSWERS / RECORD</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.dnsArtifacts.map((dns, idx) => (
                        <tr
                          key={`${dns.frameNumber}-${idx}`}
                          onClick={() => setSelectedFrame(dns.frameNumber)}
                          style={{ cursor: 'pointer' }}
                        >
                          <td className="mono">#{dns.frameNumber}</td>
                          <td>
                            <span className="status-badge" style={{ fontSize: '0.7rem' }}>
                              {dns.isResponse ? `RSP (${dns.queryType})` : `QRY (${dns.queryType})`}
                            </span>
                          </td>
                          <td className="mono">
                            <strong>{dns.queryName}</strong>
                          </td>
                          <td className="mono" style={{ fontSize: '0.78rem' }}>
                            {dns.isResponse ? (
                              dns.answers.length > 0 ? (
                                dns.answers.join(', ')
                              ) : (
                                <NotPresentBadge label="No Answer RR" />
                              )
                            ) : (
                              <span style={{ opacity: 0.65 }}>{dns.srcIp} → {dns.dstIp}</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ padding: '12px 0' }}>
                  <NotPresentBadge label="Not Present — No DNS queries or responses in capture" />
                </div>
              )}
            </section>

            <section className="analyzer-card">
              <div className="section-title">
                <h2>
                  <Eye size={17} /> HTTP Requests & TLS SNI Hostnames
                  <span className="count-badge">{result.httpTlsArtifacts.length}</span>
                </h2>
                <span className="subtle-label">APPLICATION LAYER</span>
              </div>

              {result.httpTlsArtifacts.length > 0 ? (
                <div className="table-wrap" style={{ maxHeight: 280, overflowY: 'auto' }}>
                  <table>
                    <thead>
                      <tr>
                        <th>FRAME</th>
                        <th>ARTIFACT</th>
                        <th>HOST / SNI</th>
                        <th>METHOD / URI / USER-AGENT</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.httpTlsArtifacts.map((art, idx) => (
                        <tr
                          key={`${art.frameNumber}-${idx}`}
                          onClick={() => setSelectedFrame(art.frameNumber)}
                          style={{ cursor: 'pointer' }}
                        >
                          <td className="mono">#{art.frameNumber}</td>
                          <td>
                            <span className="status-badge" style={{ fontSize: '0.7rem' }}>
                              {art.type}
                            </span>
                          </td>
                          <td className="mono">
                            {art.hostOrSni ? <strong>{art.hostOrSni}</strong> : <NotPresentBadge />}
                          </td>
                          <td className="mono" style={{ fontSize: '0.76rem' }}>
                            {art.methodOrStatus} {art.uri ?? ''}
                            {art.userAgent && (
                              <div style={{ opacity: 0.72, fontSize: '0.72rem' }}>UA: {art.userAgent}</div>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ padding: '12px 0' }}>
                  <NotPresentBadge label="Not Present — No cleartext HTTP or TLS ClientHello SNI records in capture" />
                </div>
              )}
            </section>
          </div>

          {/* Row 4: Interactive Packet Table & Frame Hex/Layer Inspector */}
          <section className="analyzer-card" style={{ marginTop: 16 }}>
            <div className="section-title" style={{ flexWrap: 'wrap', gap: 10 }}>
              <h2>
                <Network size={17} /> Source-Attributed Packet Capture Table
                <span className="count-badge">{filteredPackets.length}</span>
              </h2>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <div style={{ position: 'relative' }}>
                  <Search
                    size={14}
                    style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', opacity: 0.6 }}
                  />
                  <input
                    type="text"
                    placeholder="Filter by IP, port, DNS, HTTP, or Frame #…"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={{ paddingLeft: 28, fontSize: '0.82rem', minWidth: 260 }}
                  />
                </div>
              </div>
            </div>

            <div className="table-wrap" style={{ maxHeight: 340, overflowY: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>FRAME #</th>
                    <th>TIME (REL)</th>
                    <th>SOURCE</th>
                    <th>DESTINATION</th>
                    <th>PROTOCOL</th>
                    <th>LEN</th>
                    <th>FORENSIC SUMMARY / INFO</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredPackets.slice(0, 300).map((pkt) => {
                    const isSelected = activePacket?.frameNumber === pkt.frameNumber;
                    return (
                      <tr
                        key={pkt.frameNumber}
                        onClick={() => setSelectedFrame(pkt.frameNumber)}
                        style={{
                          cursor: 'pointer',
                          background: isSelected ? 'rgba(168, 85, 247, 0.16)' : undefined,
                        }}
                      >
                        <td className="mono">
                          <strong>#{pkt.frameNumber}</strong>
                        </td>
                        <td className="mono" style={{ fontSize: '0.78rem' }}>
                          {pkt.relativeTimeSec.toFixed(4)}s
                        </td>
                        <td className="mono">
                          {pkt.srcIp ? (
                            <>
                              {pkt.srcIp}
                              {pkt.srcPort !== null ? `:${pkt.srcPort}` : ''}
                            </>
                          ) : (
                            pkt.srcMac ?? <NotPresentBadge />
                          )}
                        </td>
                        <td className="mono">
                          {pkt.dstIp ? (
                            <>
                              {pkt.dstIp}
                              {pkt.dstPort !== null ? `:${pkt.dstPort}` : ''}
                            </>
                          ) : (
                            pkt.dstMac ?? <NotPresentBadge />
                          )}
                        </td>
                        <td>
                          <span className="status-badge" style={{ fontSize: '0.72rem' }}>
                            {pkt.transportProtocol !== 'Other' ? pkt.transportProtocol : pkt.networkProtocol}
                          </span>
                        </td>
                        <td className="mono">{pkt.capturedLen} B</td>
                        <td className="mono" style={{ fontSize: '0.78rem' }}>
                          {pkt.info}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Selected Frame Deep Decode & Hex Inspector */}
            {activePacket && (
              <div
                style={{
                  marginTop: 16,
                  padding: 14,
                  borderRadius: 10,
                  background: 'rgba(15, 23, 42, 0.65)',
                  border: '1px solid rgba(148, 163, 184, 0.18)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                  <strong>
                    Selected Packet Inspector — <span className="mono">Frame #{activePacket.frameNumber}</span> (File Offset{' '}
                    <span className="mono">0x{activePacket.fileOffset.toString(16).toUpperCase()}</span>)
                  </strong>
                  <span className="mono" style={{ fontSize: '0.78rem', opacity: 0.8 }}>
                    UTC: {activePacket.timestampIso}
                  </span>
                </div>

                <div className="analyzer-grid">
                  <div className="exif-fields-grid">
                    <div className="exif-field-row">
                      <span className="exif-label">Link Layer</span>
                      <span className="mono">
                        {activePacket.linkLayer}
                        {activePacket.srcMac ? ` (${activePacket.srcMac} → ${activePacket.dstMac})` : ''}
                      </span>
                    </div>
                    <div className="exif-field-row">
                      <span className="exif-label">Network Layer</span>
                      <span className="mono">
                        {activePacket.networkProtocol} ({activePacket.etherTypeHex ?? 'N/A'}){' '}
                        {activePacket.ttl !== null ? `· TTL=${activePacket.ttl}` : ''}
                      </span>
                    </div>
                    <div className="exif-field-row">
                      <span className="exif-label">Endpoints</span>
                      <span className="mono">
                        {activePacket.srcIp ?? 'N/A'}
                        {activePacket.srcPort !== null ? `:${activePacket.srcPort}` : ''} → {activePacket.dstIp ?? 'N/A'}
                        {activePacket.dstPort !== null ? `:${activePacket.dstPort}` : ''}
                      </span>
                    </div>
                    <div className="exif-field-row">
                      <span className="exif-label">Transport / TCP Flags</span>
                      <span className="mono">
                        {activePacket.transportProtocol}
                        {activePacket.tcpFlags ? ` [${activePacket.tcpFlags}]` : ''}
                      </span>
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.74rem', opacity: 0.7, marginBottom: 4 }}>
                      RAW FRAME BYTES (FIRST {activePacket.rawPreviewBytes.length} BYTES — HEX + ASCII)
                    </div>
                    <pre
                      className="mono"
                      style={{
                        margin: 0,
                        padding: 10,
                        borderRadius: 6,
                        background: 'rgba(0,0,0,0.45)',
                        fontSize: '0.73rem',
                        overflowX: 'auto',
                        lineHeight: 1.45,
                      }}
                    >
                      {formatHexDump(activePacket.rawPreviewBytes)}
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </section>

          {/* Row 5: Section 13 Quick Validation Reference & Independent Validation Gate */}
          <div className="analyzer-grid" style={{ marginTop: 16 }}>
            <section className="analyzer-card">
              <div className="section-title">
                <h2>
                  <Terminal size={17} /> Section 13 — Quick Validation Reference
                </h2>
                <span className="subtle-label">WIRESHARK / TSHARK / TCPDUMP</span>
              </div>
              <p style={{ fontSize: '0.84rem', opacity: 0.85, marginBottom: 12 }}>
                Independently verify DeadByte&apos;s packet count, IP conversations, and DNS/HTTP findings using{' '}
                <strong>Wireshark</strong> or the <strong>tshark</strong> CLI:
              </p>

              {[
                {
                  id: 'phs',
                  label: '1. Verify Total Packet Count & Protocol Hierarchy (tshark)',
                  cmd: `tshark -r "${targetFilename}" -q -z io,phs`,
                },
                {
                  id: 'conv',
                  label: '2. Verify IP Conversations / Top Talkers (tshark)',
                  cmd: `tshark -r "${targetFilename}" -q -z conv,ip`,
                },
                {
                  id: 'dns-http',
                  label: '3. Verify Extracted DNS Queries, HTTP Requests & TLS SNI',
                  cmd: `tshark -r "${targetFilename}" -Y "dns or http or tls.handshake.extensions_server_name"`,
                },
                {
                  id: 'hash',
                  label: '4. Verify Capture Integrity SHA-256 (PowerShell)',
                  cmd: `Get-FileHash -Algorithm SHA256 "${targetFilename}"`,
                },
              ].map((item) => (
                <div key={item.id} style={{ marginBottom: 10 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: '0.78rem', fontWeight: 600 }}>{item.label}</span>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => copyCommand(item.id, item.cmd)}
                      style={{ height: 24, padding: '0 8px' }}
                    >
                      {copiedCmd === item.id ? <Check size={13} /> : <Copy size={13} />}
                      <span style={{ marginLeft: 4, fontSize: '0.73rem' }}>
                        {copiedCmd === item.id ? 'Copied' : 'Copy'}
                      </span>
                    </Button>
                  </div>
                  <pre
                    className="mono"
                    style={{
                      margin: 0,
                      padding: '8px 10px',
                      borderRadius: 6,
                      background: 'rgba(0,0,0,0.38)',
                      fontSize: '0.76rem',
                      overflowX: 'auto',
                    }}
                  >
                    {item.cmd}
                  </pre>
                </div>
              ))}
            </section>

            {/* Independent Validation Gate */}
            <section className="analyzer-card">
              <div className="section-title">
                <h2>
                  <ShieldCheck size={17} /> Independent Validation Gate
                </h2>
                <span className="status-badge status-active">9-COLUMN LOG</span>
              </div>

              <div className="form-stack">
                <label>
                  Field / Finding to Validate
                  <select value={fieldPreset} onChange={(e) => setFieldPreset(e.target.value)}>
                    <option value="Total Packet Count">Total Packet Count & Captured Bytes</option>
                    <option value="Capture SHA-256">Capture SHA-256 Digest</option>
                    <option value="Capture Format & Link Layer">Capture Format & Link Layer</option>
                    <option value="Top IP Conversation">Top IP Conversation (Endpoints & Bytes)</option>
                    <option value="First DNS Query">First Extracted DNS Query</option>
                    <option value="First HTTP / TLS Host">First Extracted HTTP / TLS Host</option>
                  </select>
                </label>

                <label>
                  DeadByte Tool Value (Auto-Populated)
                  <input type="text" readOnly value={deadbyteToolValue} className="mono" />
                </label>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <label>
                    External Validation Tool
                    <input
                      type="text"
                      value={externalToolName}
                      onChange={(e) => setExternalToolName(e.target.value)}
                      placeholder="Wireshark 4.x / tshark"
                    />
                  </label>
                  <label>
                    Command / Filter Used
                    <input
                      type="text"
                      value={externalCommand}
                      onChange={(e) => setExternalCommand(e.target.value)}
                      placeholder='tshark -r "capture.pcap" -q -z io,phs'
                      className="mono"
                    />
                  </label>
                </div>

                <label>
                  External Tool Output (Paste Wireshark / tshark Value)
                  <input
                    type="text"
                    value={externalValue}
                    onChange={(e) => setExternalValue(e.target.value)}
                    placeholder="e.g., 42 packets (18,420 bytes) or matching conversation output"
                    className="mono"
                  />
                </label>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <label>
                    Validator (Student Name)
                    <input
                      type="text"
                      value={validatorName}
                      onChange={(e) => setValidatorName(e.target.value)}
                      placeholder="Student / Investigator Name"
                    />
                  </label>
                  <label>
                    Investigator Notes
                    <input
                      type="text"
                      value={investigatorNotes}
                      onChange={(e) => setInvestigatorNotes(e.target.value)}
                      placeholder="Optional notes on Wireshark / tshark verification"
                    />
                  </label>
                </div>

                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 4 }}>
                  <Button
                    type="button"
                    disabled={savingValidation}
                    onClick={() => submitValidation('VERIFIED')}
                  >
                    <CheckCircle2 size={15} /> Confirm VERIFIED
                  </Button>
                  <Button
                    type="button"
                    variant="destructive"
                    disabled={savingValidation}
                    onClick={() => submitValidation('MISMATCH')}
                  >
                    <XCircle size={15} /> Log MISMATCH
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    disabled={savingValidation}
                    onClick={() => submitValidation('NEEDS REVIEW')}
                  >
                    <Clock3 size={15} /> Needs Review
                  </Button>
                </div>
              </div>

              {evidenceValidations.length > 0 && (
                <div style={{ marginTop: 14, borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: 10 }}>
                  <div style={{ fontSize: '0.76rem', opacity: 0.75, marginBottom: 6 }}>
                    RECENT VALIDATIONS FOR THIS CAPTURE ({evidenceValidations.length})
                  </div>
                  {evidenceValidations.slice(0, 3).map((v) => (
                    <div
                      key={v.id}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        fontSize: '0.78rem',
                        padding: '4px 0',
                      }}
                    >
                      <span>
                        <strong>{v.algorithm ?? 'PCAP Finding'}</strong> via {v.independent_tool}
                      </span>
                      <span className="status-badge status-active">{v.status}</span>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>
        </>
      )}
    </div>
  );
}
