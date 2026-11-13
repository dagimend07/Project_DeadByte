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
  Layers,
  Upload,
  Copy,
  ShieldCheck,
  ShieldAlert,
  Archive,
  Terminal,
  ArrowUpRight,
  FileWarning,
  Bot,
  Cpu,
  HardDrive,
  FolderSearch,
  KeyRound,
  Sparkles,
  Download,
} from 'lucide-react';

export interface ExtractedRegistryEntry {
  category: 'system' | 'persistence' | 'usb' | 'user_activity' | 'other';
  keyPath: string;
  valueName: string;
  valueType: 'REG_SZ' | 'REG_DWORD' | 'REG_QWORD' | 'REG_BINARY' | 'REG_EXPAND_SZ' | 'REG_MULTI_SZ' | 'HIVE_CELL';
  valueData: string;
  rawLineOrOffset: string;
  sourceRef: string;
  suspiciousReason?: string;
}

export interface ParsedRegistryAnalysis {
  supported: boolean;
  corrupted: boolean;
  errorMessage?: string;
  detectedFormat: string;
  magicBytesHex: string;
  extensionName: string;
  extensionMismatch: boolean;
  mismatchReason?: string;
  hiveRootOrVersion: string | null;
  hiveSequenceNumbers: string | null;
  hiveLastWrittenUtc: string | null;
  totalKeysCount: number;
  totalValuesCount: number;
  // 1. OS & System Info
  productName: string | null;
  currentBuild: string | null;
  displayVersion: string | null;
  registeredOwner: string | null;
  computerName: string | null;
  timeZoneKeyName: string | null;
  installDateUtc: string | null;
  // 2. Categorized Lists
  persistenceEntries: ExtractedRegistryEntry[];
  usbEntries: ExtractedRegistryEntry[];
  userActivityEntries: ExtractedRegistryEntry[];
  allEntries: ExtractedRegistryEntry[];
  anomalies: string[];
}

const REGISTRY_INDEPENDENT_TOOLS = [
  'Windows CLI (reg query / regedit)',
  'Registry Explorer (Eric Zimmerman)',
  'RegRipper (rip.exe)',
  'Autopsy Registry Viewer',
  'Other Approved Registry Tool',
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

function decodeHexWordsToUtf16(hexCsv: string): string {
  const bytes = hexCsv
    .split(',')
    .map(s => parseInt(s.trim(), 16))
    .filter(n => !Number.isNaN(n));
  if (bytes.length === 0) return '';
  const u8 = new Uint8Array(bytes);
  try {
    return new TextDecoder('utf-16le')
      .decode(u8)
      .replace(/\0+$/g, '')
      .replace(/\0/g, ' | ')
      .trim();
  } catch {
    return hexCsv;
  }
}

function classifyRegistryKey(
  keyPath: string,
  valueName: string,
  valueData: string,
): {
  category: ExtractedRegistryEntry['category'];
  suspiciousReason?: string;
} {
  const kp = keyPath.toLowerCase();
  const vn = valueName.toLowerCase();
  const vd = valueData.toLowerCase();

  // Check for Persistence (Run / RunOnce / Winlogon / Services)
  if (
    kp.includes('\\currentversion\\run') ||
    kp.includes('\\currentversion\\runonce') ||
    kp.includes('\\currentversion\\policies\\explorer\\run') ||
    kp.includes('\\microsoft\\windows nt\\currentversion\\winlogon')
  ) {
    let suspiciousReason: string | undefined;
    if (
      vd.includes('\\appdata\\local\\temp') ||
      vd.includes('\\users\\public') ||
      vd.includes('powershell') ||
      vd.includes('cmd.exe /c') ||
      vd.includes('mshta') ||
      vd.includes('wscript') ||
      vd.includes('regsvr32') ||
      vd.includes('-enc')
    ) {
      suspiciousReason = `Suspicious autostart execution path or interpreter in ${keyPath} -> ${valueName}: "${valueData}"`;
    }
    return { category: 'persistence', suspiciousReason };
  }

  // Check for USB / Removable Storage History
  if (
    kp.includes('\\enum\\usbstor') ||
    kp.includes('\\enum\\usb\\') ||
    kp.includes('\\mounteddevices') ||
    kp.includes('\\portable devices')
  ) {
    return { category: 'usb' };
  }

  // Check for User Activity (TypedPaths, RecentDocs, RunMRU, UserAssist, OpenSavePidlMRU)
  if (
    kp.includes('\\explorer\\typedpaths') ||
    kp.includes('\\explorer\\recentdocs') ||
    kp.includes('\\explorer\\runmru') ||
    kp.includes('\\explorer\\userassist') ||
    kp.includes('\\explorer\\comdlg32') ||
    kp.includes('\\currentversion\\uninstall')
  ) {
    return { category: 'user_activity' };
  }

  // Check for OS / System Identity
  if (
    kp.includes('\\microsoft\\windows nt\\currentversion') ||
    kp.includes('\\control\\computername') ||
    kp.includes('\\control\\timezoneinformation') ||
    vn === 'productname' ||
    vn === 'currentbuild' ||
    vn === 'computername' ||
    vn === 'timezonekeyname'
  ) {
    return { category: 'system' };
  }

  return { category: 'other' };
}

/**
 * Generates a realistic Windows Registry export (.reg) containing all 4 forensic categories:
 * 1) OS & System Identity (Windows 11 Pro, Build 22631, WORKSTATION-DFIR01, Eastern Standard Time)
 * 2) Autostart / Persistence (OneDrive, SecurityHealth, and a suspicious Temp Beacon updater)
 * 3) USB Storage History (SanDisk Ultra USB 3.0 & Kingston DataTraveler + MountedDevices)
 * 4) User Activity (TypedPaths, RunMRU, RecentDocs)
 */
export function createSampleForensicRegFile(): File {
  const regContent = `Windows Registry Editor Version 5.00

; DeadByte Forensic Sample Registry Evidence (NWIT 263 Module 4)

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion]
"ProductName"="Windows 11 Pro"
"DisplayVersion"="23H2"
"CurrentBuild"="22631"
"RegisteredOwner"="Alex Rivera (Cyber Lab)"
"SystemRoot"="C:\\\\Windows"
"InstallDate"=dword:65f86180

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName]
"ComputerName"="WORKSTATION-DFIR01"

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation]
"TimeZoneKeyName"="Eastern Standard Time"
"ActiveTimeBias"=dword:000000f0

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
"OneDrive"="\\"C:\\\\Users\\\\arivera\\\\AppData\\\\Local\\\\Microsoft\\\\OneDrive\\\\OneDrive.exe\\" /background"
"SysHealthUpdater"="powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\\\Users\\\\arivera\\\\AppData\\\\Local\\\\Temp\\\\stage2_beacon.ps1"

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]
"SecurityHealth"="C:\\\\Windows\\\\system32\\\\SecurityHealthSystray.exe"
"PublicDropper"="C:\\\\Users\\\\Public\\\\Downloads\\\\svchost_helper.exe --silent"

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra_USB_3.0&Rev_1.00\\4C530001190822114312&0]
"FriendlyName"="SanDisk Ultra USB 3.0 USB Device"
"HardwareID"="USBSTOR\\\\DiskSanDisk_Ultra_USB_3.0___1.00"
"Mfg"="Compatible USB storage device"
"Service"="disk"

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\\60A44C4138F9F190B991&0]
"FriendlyName"="Kingston DataTraveler 3.0 USB Device"
"HardwareID"="USBSTOR\\\\DiskKingstonDataTraveler_3.0PMAP"
"Service"="disk"

[HKEY_LOCAL_MACHINE\\SYSTEM\\MountedDevices]
"\\\\DosDevices\\\\E:"="USBSTOR#Disk&Ven_SanDisk&Prod_Ultra_USB_3.0&Rev_1.00#4C530001190822114312&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
"\\\\DosDevices\\\\F:"="USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP#60A44C4138F9F190B991&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths]
"url1"="C:\\\\Users\\\\arivera\\\\Downloads\\\\Confidential_Q3_Export"
"url2"="\\\\\\\\192.168.1.45\\\\StagingShare\\\\exfil_archive"
"url3"="E:\\\\Stolen_Schemas"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU]
"a"="cmd.exe /c whoami /all\\\\1"
"b"="regedit.exe\\\\1"
"c"="powershell.exe -ep bypass\\\\1"
"MRUList"="cba"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs]
"0"="Payroll_2026_Backup.xlsx.lnk"
"1"="Customer_Credentials_Dump.sqlite.lnk"
"2"="stage2_beacon.ps1.lnk"
`;
  return new File([regContent], 'WORKSTATION_DFIR01_Registry_Export.reg', {
    type: 'text/plain',
    lastModified: Date.now(),
  });
}

/**
 * Deterministic parser for Windows Registry (.reg text exports in UTF-16LE / UTF-8
 * and binary 'regf' Windows Registry Hive files).
 */
export function parseRegistryEvidenceBuffer(
  buffer: ArrayBuffer,
  filename: string,
): ParsedRegistryAnalysis {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const extMatch = filename.toLowerCase().match(/\.([a-z0-9]+)$/);
  const ext = extMatch ? extMatch[1] : 'none';
  const magicHex = bytesToHex(bytes, 8);
  const allEntries: ExtractedRegistryEntry[] = [];
  const anomalies: string[] = [];

  const base: ParsedRegistryAnalysis = {
    supported: false,
    corrupted: false,
    detectedFormat: 'Unknown Binary',
    magicBytesHex: magicHex,
    extensionName: `.${ext}`,
    extensionMismatch: false,
    hiveRootOrVersion: null,
    hiveSequenceNumbers: null,
    hiveLastWrittenUtc: null,
    totalKeysCount: 0,
    totalValuesCount: 0,
    productName: null,
    currentBuild: null,
    displayVersion: null,
    registeredOwner: null,
    computerName: null,
    timeZoneKeyName: null,
    installDateUtc: null,
    persistenceEntries: [],
    usbEntries: [],
    userActivityEntries: [],
    allEntries,
    anomalies,
  };

  if (bytes.length === 0) {
    return {
      ...base,
      corrupted: true,
      errorMessage: 'Empty file (0 bytes). Cannot extract Windows Registry artifacts.',
    };
  }

  // 1. Check for Binary Windows Registry Hive ('regf' = 0x72 0x65 0x67 0x66)
  const isRegfHive =
    bytes.length >= 4 &&
    bytes[0] === 0x72 &&
    bytes[1] === 0x65 &&
    bytes[2] === 0x67 &&
    bytes[3] === 0x66;

  // 2. Check for Text .reg Export (UTF-16LE BOM 0xFF 0xFE, UTF-8 BOM, or plain ASCII)
  let decodedText = '';
  const isUtf16Le = bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe;
  if (!isRegfHive) {
    try {
      decodedText = new TextDecoder(isUtf16Le ? 'utf-16le' : 'utf-8').decode(bytes);
    } catch {
      decodedText = '';
    }
  }

  const trimmedText = decodedText.replace(/^\uFEFF/, '').trimStart();
  const isRegTextExport =
    !isRegfHive &&
    (trimmedText.startsWith('Windows Registry Editor Version') ||
      trimmedText.startsWith('REGEDIT4') ||
      /^\[(HKEY_|HKLM|HKCU|HKCR|HKU|HKCC)/m.test(trimmedText));

  if (isRegfHive) {
    base.supported = true;
    base.detectedFormat = 'Windows Registry Binary Hive (regf)';
    if (['jpg', 'jpeg', 'png', 'pdf', 'zip', 'exe', 'pcap'].includes(ext)) {
      base.extensionMismatch = true;
      base.mismatchReason = `File has extension ".${ext}", but binary signature (${magicHex}) is a Windows Registry Hive (regf).`;
      anomalies.push(base.mismatchReason);
    }

    if (bytes.length < 64) {
      base.corrupted = true;
      base.errorMessage =
        'CORRUPTED REGISTRY HIVE: Valid "regf" signature found, but base block header (< 64 bytes) is truncated.';
      return base;
    }

    // Parse regf base block fields
    const seq1 = view.getUint32(4, true);
    const seq2 = view.getUint32(8, true);
    base.hiveSequenceNumbers = `Primary: ${seq1} · Secondary: ${seq2} (${
      seq1 === seq2 ? 'Clean / Synced' : 'Dirty / Unflushed Log'
    })`;
    if (seq1 !== seq2) {
      anomalies.push(
        `Hive sequence numbers differ (Seq1=${seq1}, Seq2=${seq2}), indicating the hive was not cleanly unmounted or has pending transaction logs.`,
      );
    }

    // Windows FILETIME at offset 12 (100-ns intervals since Jan 1, 1601 UTC)
    const ftLow = BigInt(view.getUint32(12, true));
    const ftHigh = BigInt(view.getUint32(16, true));
    const filetime = (ftHigh << 32n) | ftLow;
    if (filetime > 116444736000000000n) {
      const unixMs = Number((filetime - 116444736000000000n) / 10000n);
      if (unixMs > 0 && unixMs < 4102444800000) {
        base.hiveLastWrittenUtc = new Date(unixMs)
          .toISOString()
          .replace('T', ' ')
          .slice(0, 19) + ' UTC';
      }
    }

    const majorVer = view.getUint32(20, true);
    const minorVer = view.getUint32(24, true);
    let embeddedFileName = '';
    if (bytes.length >= 112) {
      embeddedFileName = new TextDecoder('utf-16le')
        .decode(bytes.slice(48, 112))
        .replace(/\0+$/g, '')
        .trim();
    }
    base.hiveRootOrVersion = `Hive Format v${majorVer}.${minorVer}${
      embeddedFileName ? ` (${embeddedFileName})` : ''
    }`;

    // Scan hive bins ('hbin') for Named Key ('nk') and Value Key ('vk') cells
    const maxScan = Math.min(bytes.length - 32, 2 * 1024 * 1024);
    const seenKeys = new Set<string>();
    for (let i = 4096; i < maxScan; i++) {
      // 'n' 'k' cell signature (0x6E 0x6B)
      if (bytes[i] === 0x6e && bytes[i + 1] === 0x6b && i + 76 < bytes.length) {
        const nameLen = view.getUint16(i + 72, true);
        if (nameLen >= 3 && nameLen <= 128 && i + 76 + nameLen <= bytes.length) {
          const keyName = readAscii(view, i + 76, nameLen);
          if (keyName.length >= 3 && /^[A-Za-z0-9_.\-\\ ()&]+$/.test(keyName)) {
            seenKeys.add(keyName);
            if (seenKeys.size <= 150) {
              const cls = classifyRegistryKey(keyName, '(Hive Key Node)', keyName);
              const entry: ExtractedRegistryEntry = {
                category: cls.category,
                keyPath: keyName,
                valueName: '(nk Key Node)',
                valueType: 'HIVE_CELL',
                valueData: `Key Cell @ 0x${i.toString(16).toUpperCase()}`,
                rawLineOrOffset: `0x${i.toString(16).toUpperCase()}`,
                sourceRef: `Hive:nk@0x${i.toString(16).toUpperCase()} (${keyName})`,
              };
              allEntries.push(entry);
              if (cls.category === 'persistence') base.persistenceEntries.push(entry);
              if (cls.category === 'usb') base.usbEntries.push(entry);
              if (cls.category === 'user_activity') base.userActivityEntries.push(entry);
            }
          }
        }
      }
    }
    base.totalKeysCount = seenKeys.size;
    base.totalValuesCount = allEntries.length;
    return base;
  }

  if (isRegTextExport) {
    base.supported = true;
    base.detectedFormat = isUtf16Le
      ? 'Windows Registry Export (.reg · UTF-16LE)'
      : 'Windows Registry Export (.reg · UTF-8/ASCII)';
    if (!['reg', 'txt', 'hiv', 'dat'].includes(ext)) {
      base.extensionMismatch = true;
      base.mismatchReason = `File has extension ".${ext}", but header identifies it as a Windows Registry Export (.reg).`;
      anomalies.push(base.mismatchReason);
    }

    // Join multi-line backslash continuations in .reg files
    const rawLines = trimmedText.replace(/\r\n/g, '\n').split('\n');
    const logicalLines: { text: string; lineNo: number }[] = [];
    let currentLine = '';
    let startLineNo = 1;

    for (let i = 0; i < rawLines.length; i++) {
      const line = rawLines[i].trim();
      if (!currentLine) startLineNo = i + 1;
      if (line.endsWith('\\')) {
        currentLine += line.slice(0, -1).trim();
      } else {
        currentLine += line;
        logicalLines.push({ text: currentLine, lineNo: startLineNo });
        currentLine = '';
      }
    }
    if (currentLine) {
      logicalLines.push({ text: currentLine, lineNo: startLineNo });
    }

    if (logicalLines.length > 0 && logicalLines[0].text.startsWith('Windows Registry Editor')) {
      base.hiveRootOrVersion = logicalLines[0].text;
    } else if (logicalLines.length > 0 && logicalLines[0].text.startsWith('REGEDIT4')) {
      base.hiveRootOrVersion = 'REGEDIT4 (Legacy Registry Export)';
    } else {
      base.hiveRootOrVersion = 'Windows Registry Key Export';
    }

    let currentKeyPath = '';
    const uniqueKeys = new Set<string>();

    for (const { text, lineNo } of logicalLines) {
      if (!text || text.startsWith(';')) continue;
      if (text.startsWith('Windows Registry Editor') || text.startsWith('REGEDIT4')) continue;

      if (text.startsWith('[') && text.endsWith(']')) {
        currentKeyPath = text.slice(1, -1).trim();
        uniqueKeys.add(currentKeyPath);

        // If the key path itself is a USBSTOR device key, record the device key even if values are minimal
        if (currentKeyPath.toLowerCase().includes('\\enum\\usbstor\\')) {
          const parts = currentKeyPath.split('\\');
          const serialPart = parts[parts.length - 1] || '';
          const devicePart = parts[parts.length - 2] || '';
          if (devicePart.toLowerCase().startsWith('disk&')) {
            const usbKeyEntry: ExtractedRegistryEntry = {
              category: 'usb',
              keyPath: currentKeyPath,
              valueName: '(USB Device Key)',
              valueType: 'REG_SZ',
              valueData: `${devicePart} · Serial/Instance: ${serialPart}`,
              rawLineOrOffset: `Line ${lineNo}`,
              sourceRef: `${currentKeyPath} (Line ${lineNo})`,
            };
            allEntries.push(usbKeyEntry);
            base.usbEntries.push(usbKeyEntry);
          }
        }
        continue;
      }

      if (!currentKeyPath) continue;

      // Parse "ValueName"=Data or @=Data
      let valueName = '';
      let rawRhs = '';

      if (text.startsWith('@=')) {
        valueName = '(Default)';
        rawRhs = text.slice(2).trim();
      } else if (text.startsWith('"')) {
        // Find closing quote for valueName (handling escaped \" inside name)
        let idx = 1;
        while (idx < text.length) {
          if (text[idx] === '\\' && idx + 1 < text.length) {
            idx += 2;
            continue;
          }
          if (text[idx] === '"') break;
          idx++;
        }
        valueName = text
          .slice(1, idx)
          .replace(/\\"/g, '"')
          .replace(/\\\\/g, '\\');
        const eqPos = text.indexOf('=', idx);
        if (eqPos !== -1) {
          rawRhs = text.slice(eqPos + 1).trim();
        }
      }

      if (!valueName || !rawRhs) continue;

      let valueType: ExtractedRegistryEntry['valueType'] = 'REG_SZ';
      let valueData = rawRhs;

      if (rawRhs.startsWith('"') && rawRhs.endsWith('"')) {
        valueType = 'REG_SZ';
        valueData = rawRhs
          .slice(1, -1)
          .replace(/\\"/g, '"')
          .replace(/\\\\/g, '\\');
      } else if (rawRhs.toLowerCase().startsWith('dword:')) {
        valueType = 'REG_DWORD';
        const hexStr = rawRhs.slice(6).trim();
        const decVal = parseInt(hexStr, 16);
        valueData = Number.isNaN(decVal)
          ? `0x${hexStr}`
          : `0x${hexStr.toUpperCase()} (${decVal})`;
      } else if (rawRhs.toLowerCase().startsWith('hex(b):')) {
        valueType = 'REG_QWORD';
        valueData = rawRhs.slice(7).trim();
      } else if (rawRhs.toLowerCase().startsWith('hex(2):')) {
        valueType = 'REG_EXPAND_SZ';
        const decoded = decodeHexWordsToUtf16(rawRhs.slice(7));
        valueData = decoded || rawRhs;
      } else if (rawRhs.toLowerCase().startsWith('hex(7):')) {
        valueType = 'REG_MULTI_SZ';
        const decoded = decodeHexWordsToUtf16(rawRhs.slice(7));
        valueData = decoded || rawRhs;
      } else if (rawRhs.toLowerCase().startsWith('hex:')) {
        valueType = 'REG_BINARY';
        const hexPreview = rawRhs.slice(4).trim();
        valueData =
          hexPreview.length > 72 ? `${hexPreview.slice(0, 72)}…` : hexPreview;
      }

      const cls = classifyRegistryKey(currentKeyPath, valueName, valueData);
      const entry: ExtractedRegistryEntry = {
        category: cls.category,
        keyPath: currentKeyPath,
        valueName,
        valueType,
        valueData,
        rawLineOrOffset: `Line ${lineNo}`,
        sourceRef: `${currentKeyPath} -> ${valueName} (Line ${lineNo})`,
        suspiciousReason: cls.suspiciousReason,
      };

      allEntries.push(entry);
      if (cls.suspiciousReason) {
        anomalies.push(cls.suspiciousReason);
      }

      if (cls.category === 'persistence') {
        base.persistenceEntries.push(entry);
      } else if (cls.category === 'usb') {
        base.usbEntries.push(entry);
      } else if (cls.category === 'user_activity') {
        base.userActivityEntries.push(entry);
      }

      // Populate top-level System Identity fields if present
      const vnLower = valueName.toLowerCase();
      if (vnLower === 'productname' && !base.productName) {
        base.productName = valueData;
      } else if (
        (vnLower === 'currentbuild' || vnLower === 'currentbuildnumber') &&
        !base.currentBuild
      ) {
        base.currentBuild = valueData;
      } else if (vnLower === 'displayversion' && !base.displayVersion) {
        base.displayVersion = valueData;
      } else if (vnLower === 'registeredowner' && !base.registeredOwner) {
        base.registeredOwner = valueData;
      } else if (vnLower === 'computername' && !base.computerName) {
        base.computerName = valueData;
      } else if (vnLower === 'timezonekeyname' && !base.timeZoneKeyName) {
        base.timeZoneKeyName = valueData;
      } else if (vnLower === 'installdate' && !base.installDateUtc) {
        const epochMatch = valueData.match(/\((\d+)\)/);
        const epochSec = epochMatch ? Number(epochMatch[1]) : Number(valueData);
        if (!Number.isNaN(epochSec) && epochSec > 946684800) {
          base.installDateUtc =
            new Date(epochSec * 1000)
              .toISOString()
              .replace('T', ' ')
              .slice(0, 19) + ' UTC';
        } else {
          base.installDateUtc = valueData;
        }
      }
    }

    base.totalKeysCount = uniqueKeys.size;
    base.totalValuesCount = allEntries.length;

    if (uniqueKeys.size === 0) {
      base.corrupted = true;
      base.errorMessage =
        'CORRUPTED / EMPTY REGISTRY EXPORT: Header found, but no valid [HKEY_...] key sections could be parsed.';
    }

    return base;
  }

  // Unsupported or spoofed extension check
  if (['reg', 'hiv', 'dat'].includes(ext)) {
    base.extensionMismatch = true;
    base.mismatchReason = `RENAMED / SPOOFED EXTENSION: File is named ".${ext}", but its binary header (${magicHex}) is neither a Windows Registry Editor export (.reg) nor a binary Registry hive (regf).`;
    anomalies.push(base.mismatchReason);
  }

  base.supported = false;
  base.errorMessage = base.extensionMismatch
    ? base.mismatchReason
    : `UNSUPPORTED FILE TYPE: Binary signature (${magicHex}) is not a valid Windows Registry export (.reg) or binary hive (regf). No registry artifacts were fabricated.`;
  return base;
}

function FieldRow({
  label,
  value,
  sourceRef,
  mono = false,
}: {
  label: string;
  value: string | null | undefined;
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

export function RegistryAnalyzer() {
  const { user, cases, evidence, validations, refresh } = useWorkspace();

  const [mode, setMode] = useState<'evidence' | 'standalone'>('evidence');
  const [caseFilter, setCaseFilter] = useState('all');
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string>('');
  const [analysis, setAnalysis] = useState<ParsedRegistryAnalysis | null>(null);
  const [loading, setLoading] = useState(false);

  // Standalone file state
  const [standaloneFile, setStandaloneFile] = useState<File | null>(null);
  const [standaloneAnalysis, setStandaloneAnalysis] = useState<ParsedRegistryAnalysis | null>(
    null,
  );
  const standaloneInputRef = useRef<HTMLInputElement>(null);

  // Filter for raw registry table
  const [tableCategoryFilter, setTableCategoryFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Independent Validation Gate state (Section 3, Module 4 & Section 9.2)
  const [independentTool, setIndependentTool] = useState<string>(
    REGISTRY_INDEPENDENT_TOOLS[0],
  );
  const [valArtifact1, setValArtifact1] = useState('');
  const [valArtifact2, setValArtifact2] = useState('');
  const [valArtifact3, setValArtifact3] = useState('');
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

  const populateDefaultValidationFields = (parsed: ParsedRegistryAnalysis) => {
    const f1 =
      parsed.productName || parsed.computerName
        ? `OS/Host: ${[parsed.productName, parsed.computerName].filter(Boolean).join(' · ')}`
        : `Format: ${parsed.detectedFormat} (${parsed.totalKeysCount} keys)`;
    const f2 =
      parsed.persistenceEntries.length > 0
        ? `Run/Persistence: ${parsed.persistenceEntries[0].valueName} = ${parsed.persistenceEntries[0].valueData}`
        : `Run/Persistence Keys: Not Present`;
    const f3 =
      parsed.usbEntries.length > 0
        ? `USBSTOR: ${parsed.usbEntries[0].valueData}`
        : parsed.userActivityEntries.length > 0
          ? `User Activity: ${parsed.userActivityEntries[0].valueName} = ${parsed.userActivityEntries[0].valueData}`
          : `USB / User Activity: Not Present`;
    setValArtifact1(f1);
    setValArtifact2(f2);
    setValArtifact3(f3);
  };

  // Parse selected evidence item from Evidence Locker
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
                'Original evidence binary not found in local IndexedDB. Switch to Standalone Registry Inspector or re-upload the .reg / hive file.',
              detectedFormat: 'Unavailable',
              magicBytesHex: 'N/A',
              extensionName: selectedEvidence.filename,
              extensionMismatch: false,
              hiveRootOrVersion: null,
              hiveSequenceNumbers: null,
              hiveLastWrittenUtc: null,
              totalKeysCount: 0,
              totalValuesCount: 0,
              productName: null,
              currentBuild: null,
              displayVersion: null,
              registeredOwner: null,
              computerName: null,
              timeZoneKeyName: null,
              installDateUtc: null,
              persistenceEntries: [],
              usbEntries: [],
              userActivityEntries: [],
              allEntries: [],
              anomalies: [],
            });
          }
          return;
        }

        const buffer = await blob.arrayBuffer();
        const parsed = parseRegistryEvidenceBuffer(buffer, selectedEvidence.filename);

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
      const parsed = parseRegistryEvidenceBuffer(buffer, standaloneFile.name);
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

  const handleLoadSampleRegFile = () => {
    const sample = createSampleForensicRegFile();
    setMode('standalone');
    setStandaloneFile(sample);
    toast.success(
      'Loaded sample forensic Windows Registry export (WORKSTATION_DFIR01_Registry_Export.reg)!',
    );
  };

  const handleDownloadSampleRegFile = () => {
    const sample = createSampleForensicRegFile();
    const url = URL.createObjectURL(sample);
    const a = document.createElement('a');
    a.href = url;
    a.download = sample.name;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Downloaded ${sample.name} — you can also upload it to your Evidence Locker!`);
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
  const registryValidations = selectedEvidence
    ? validations.filter(v => v.evidence_id === selectedEvidence.id && v.module === 'Registry')
    : [];

  async function copyText(label: string, text: string) {
    await navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard.`);
  }

  async function handleRegistryValidationSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!activeData) return;
    const confirmedValues = [
      valArtifact1.trim(),
      valArtifact2.trim(),
      valArtifact3.trim(),
    ].filter(Boolean);
    if (confirmedValues.length < 2) {
      toast.error(
        'Please confirm at least 2 extracted Registry artifacts (or "Not Present" if absent) to log validation.',
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
        : standaloneFile?.name ?? 'registry_export.reg';

      const platformSummary = [
        `${activeData.totalKeysCount} keys / ${activeData.totalValuesCount} values`,
        activeData.productName || activeData.computerName
          ? `Host: ${[activeData.productName, activeData.computerName].filter(Boolean).join(' ')}`
          : 'OS Info: Not Present',
        `Persistence: ${activeData.persistenceEntries.length} | USB: ${activeData.usbEntries.length}`,
      ].join(' | ');

      saveValidationRecord({
        case_id: targetEvidence?.case_id ?? relatedCase?.id ?? 'local-case',
        case_number: relatedCase?.case_number ?? 'DB-LOCAL',
        evidence_id: targetEvidence?.id ?? 'standalone-registry',
        evidence_code: evCode,
        filename: targetName,
        module: 'Registry',
        algorithm: 'Registry Key/Value Attribution',
        platform_result: platformSummary,
        independent_tool: independentTool,
        independent_result: confirmedValues.join(' | '),
        status: valStatus,
        validator: validatorName.trim(),
        notes:
          validationNotes.trim() ||
          `Confirmed Registry keys & values with ${independentTool}.`,
      });

      await refresh();
      setValidationNotes('');
      toast.success(
        `Registry validation (${valStatus}) recorded for ${evCode} in Validation Log.`,
      );
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : 'Could not save Registry validation.',
      );
    } finally {
      setSavingVal(false);
    }
  }

  const filteredTableEntries = (activeData?.allEntries ?? []).filter(entry => {
    const matchesCat =
      tableCategoryFilter === 'all' || entry.category === tableCategoryFilter;
    const q = searchQuery.trim().toLowerCase();
    const matchesSearch =
      !q ||
      entry.keyPath.toLowerCase().includes(q) ||
      entry.valueName.toLowerCase().includes(q) ||
      entry.valueData.toLowerCase().includes(q);
    return matchesCat && matchesSearch;
  });

  return (
    <div className="hash-analyzer">
      {/* Top Mode Bar */}
      <div className="analyzer-controls">
        <div className="mode-tabs" role="tablist" aria-label="Registry analyzer mode">
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'evidence'}
            className={`mode-tab ${mode === 'evidence' ? 'active' : ''}`}
            onClick={() => setMode('evidence')}
          >
            <Archive size={15} />
            <span>Inspect Evidence Locker Registry</span>
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
            <span>Standalone Registry Inspector</span>
          </button>
        </div>

        <div className="algo-bar">
          <span className="detail-label" style={{ marginBottom: 0 }}>
            SUPPORTED FORMATS:
          </span>
          <span className="algo-tag">.REG Export (UTF-16 / UTF-8)</span>
          <span className="algo-tag">Binary Hive (regf)</span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleLoadSampleRegFile}
          >
            <Sparkles size={13} />
            Load Sample Forensic .REG
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={handleDownloadSampleRegFile}
            title="Download sample .reg file to your computer"
          >
            <Download size={13} />
            Download .REG
          </Button>
        </div>
      </div>

      {/* Selector Bar */}
      {mode === 'evidence' ? (
        evidence.length === 0 ? (
          <Empty
            icon={Layers}
            title="No evidence files in your locker yet"
            description="Upload a Windows Registry export (.reg) or hive file in the Evidence Locker, switch to Standalone Registry Inspector, or click 'Load Sample Forensic .REG' to test all 4 artifact categories."
          >
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <Button asChild variant="outline" size="sm">
                <Link to="/evidence">
                  Open Evidence Locker
                  <ArrowUpRight />
                </Link>
              </Button>
              <Button variant="default" size="sm" onClick={() => setMode('standalone')}>
                <Layers size={14} />
                Use Standalone Registry Inspector
              </Button>
              <Button variant="outline" size="sm" onClick={handleLoadSampleRegFile}>
                <Sparkles size={14} />
                Load Sample Forensic .REG
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
                Choose .reg export or binary hive from computer
              </Button>
              <Button
                type="button"
                variant="default"
                onClick={handleLoadSampleRegFile}
              >
                <Sparkles size={14} />
                Load Sample Forensic .REG Evidence
              </Button>
            </div>
            <p>
              {standaloneFile
                ? `${standaloneFile.name} · ${(standaloneFile.size / 1024).toFixed(2)} KB`
                : 'Drop a Windows Registry Export (.reg) or binary hive (NTUSER.DAT, SYSTEM, SOFTWARE, SAM) here'}
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
            Parsing Windows Registry structure and extracting forensic key paths…
          </p>
        </div>
      )}

      {activeData && !loading && (
        <>
          {/* Binary Signature / Renamed Extension / Unsupported / Corrupted Banner (Section 9.1) */}
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
                    ? 'UNSUPPORTED OR NON-REGISTRY FILE FORMAT DETECTED'
                    : activeData.corrupted
                      ? 'CORRUPTED / TRUNCATED REGISTRY EVIDENCE DETECTED'
                      : 'FILE EXTENSION vs. REGISTRY HEADER MISMATCH'}
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
            <div className="analyzer-grid">
              {/* Left Column: Extracted Registry Artifact Categories */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                {/* Card 1: OS & System Identity */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <Cpu size={17} />1 · Registry Header & System Identity
                    </h2>
                    <span className="algo-tag">
                      {selectedEvidenceCode} · {activeFilename}
                    </span>
                  </div>

                  <div className="exif-fields-grid">
                    <FieldRow
                      label="DETECTED REGISTRY FORMAT"
                      value={activeData.detectedFormat}
                      sourceRef={`Magic: ${activeData.magicBytesHex}`}
                    />
                    <FieldRow
                      label="HIVE HEADER / EXPORT VERSION"
                      value={activeData.hiveRootOrVersion}
                      sourceRef="File Header"
                      mono
                    />
                    <FieldRow
                      label="EXTRACTED KEYS & VALUES"
                      value={`${activeData.totalKeysCount} Keys · ${activeData.totalValuesCount} Values`}
                      sourceRef="Deterministic Parser"
                      mono
                    />
                    <FieldRow
                      label="OS PRODUCT NAME & VERSION"
                      value={
                        [activeData.productName, activeData.displayVersion]
                          .filter(Boolean)
                          .join(' ') || null
                      }
                      sourceRef="CurrentVersion -> ProductName"
                    />
                    <FieldRow
                      label="OS BUILD NUMBER"
                      value={activeData.currentBuild}
                      sourceRef="CurrentVersion -> CurrentBuild"
                      mono
                    />
                    <FieldRow
                      label="COMPUTER / HOSTNAME"
                      value={activeData.computerName}
                      sourceRef="Control\\ComputerName -> ComputerName"
                      mono
                    />
                    <FieldRow
                      label="REGISTERED OWNER"
                      value={activeData.registeredOwner}
                      sourceRef="CurrentVersion -> RegisteredOwner"
                    />
                    <FieldRow
                      label="SYSTEM TIMEZONE"
                      value={activeData.timeZoneKeyName}
                      sourceRef="Control\\TimeZoneInformation -> TimeZoneKeyName"
                      mono
                    />
                    <FieldRow
                      label="OS INSTALL TIMESTAMP (UTC)"
                      value={activeData.installDateUtc || activeData.hiveLastWrittenUtc}
                      sourceRef="CurrentVersion -> InstallDate / Hive Header"
                      mono
                    />
                    <FieldRow
                      label="HIVE SEQUENCE INTEGRITY"
                      value={activeData.hiveSequenceNumbers}
                      sourceRef="regf:0x04-0x0B"
                      mono
                    />
                  </div>
                </section>

                {/* Card 2: Autostart & Persistence Keys (Run / RunOnce) */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <KeyRound size={17} />2 · Autostart & Persistence Keys (Run / RunOnce)
                    </h2>
                    <span className="count-badge">
                      {activeData.persistenceEntries.length}
                    </span>
                  </div>

                  {activeData.persistenceEntries.length === 0 ? (
                    <div className="exif-field-row">
                      <div>
                        <div className="detail-label" style={{ marginBottom: 3 }}>
                          RUN / RUNONCE PERSISTENCE ARTIFACTS
                        </div>
                        <span className="not-present-badge">Not Present</span>
                      </div>
                      <span className="mono muted" style={{ fontSize: 9 }}>
                        *\CurrentVersion\Run
                      </span>
                    </div>
                  ) : (
                    <div className="hash-list">
                      {activeData.persistenceEntries.map((item, idx) => (
                        <div
                          key={`${item.sourceRef}-${idx}`}
                          className="hash-item"
                          style={
                            item.suspiciousReason
                              ? {
                                  borderColor:
                                    'color-mix(in oklch, var(--amber) 55%, var(--border))',
                                }
                              : undefined
                          }
                        >
                          <div className="hash-item-top">
                            <span className="algo-tag">{item.valueName}</span>
                            <span className="mono muted" style={{ fontSize: 9 }}>
                              {item.valueType} · {item.rawLineOrOffset}
                            </span>
                            {item.suspiciousReason && (
                              <span className="status-badge status-review">
                                SUSPICIOUS PATH / INTERPRETER
                              </span>
                            )}
                          </div>
                          <div className="hash-value" style={{ marginTop: 4 }}>
                            {item.valueData}
                          </div>
                          <small
                            className="mono muted"
                            style={{ display: 'block', marginTop: 4, fontSize: 9 }}
                          >
                            Key Path: {item.keyPath}
                          </small>
                        </div>
                      ))}
                    </div>
                  )}
                </section>

                {/* Card 3: USB & Removable Storage History (USBSTOR & MountedDevices) */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <HardDrive size={17} />3 · USB & Removable Storage History (USBSTOR)
                    </h2>
                    <span className="count-badge">{activeData.usbEntries.length}</span>
                  </div>

                  {activeData.usbEntries.length === 0 ? (
                    <div className="exif-field-row">
                      <div>
                        <div className="detail-label" style={{ marginBottom: 3 }}>
                          USBSTOR / MOUNTEDDEVICES ARTIFACTS
                        </div>
                        <span className="not-present-badge">Not Present</span>
                      </div>
                      <span className="mono muted" style={{ fontSize: 9 }}>
                        SYSTEM\CurrentControlSet\Enum\USBSTOR
                      </span>
                    </div>
                  ) : (
                    <div className="hash-list">
                      {activeData.usbEntries.map((item, idx) => (
                        <div key={`${item.sourceRef}-${idx}`} className="hash-item">
                          <div className="hash-item-top">
                            <span className="algo-tag">{item.valueName}</span>
                            <span className="mono muted" style={{ fontSize: 9 }}>
                              {item.rawLineOrOffset}
                            </span>
                          </div>
                          <div className="hash-value" style={{ marginTop: 4 }}>
                            {item.valueData}
                          </div>
                          <small
                            className="mono muted"
                            style={{ display: 'block', marginTop: 4, fontSize: 9 }}
                          >
                            Key Path: {item.keyPath}
                          </small>
                        </div>
                      ))}
                    </div>
                  )}
                </section>

                {/* Card 4: User Activity (TypedPaths, RecentDocs, RunMRU) */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <FolderSearch size={17} />4 · User Activity (TypedPaths, RunMRU, RecentDocs)
                    </h2>
                    <span className="count-badge">
                      {activeData.userActivityEntries.length}
                    </span>
                  </div>

                  {activeData.userActivityEntries.length === 0 ? (
                    <div className="exif-field-row">
                      <div>
                        <div className="detail-label" style={{ marginBottom: 3 }}>
                          EXPLORER MRU / USER ACTIVITY ARTIFACTS
                        </div>
                        <span className="not-present-badge">Not Present</span>
                      </div>
                      <span className="mono muted" style={{ fontSize: 9 }}>
                        Software\Microsoft\Windows\CurrentVersion\Explorer
                      </span>
                    </div>
                  ) : (
                    <div className="hash-list">
                      {activeData.userActivityEntries.map((item, idx) => (
                        <div key={`${item.sourceRef}-${idx}`} className="hash-item">
                          <div className="hash-item-top">
                            <span className="algo-tag">{item.valueName}</span>
                            <span className="mono muted" style={{ fontSize: 9 }}>
                              {item.valueType} · {item.rawLineOrOffset}
                            </span>
                          </div>
                          <div className="hash-value" style={{ marginTop: 4 }}>
                            {item.valueData}
                          </div>
                          <small
                            className="mono muted"
                            style={{ display: 'block', marginTop: 4, fontSize: 9 }}
                          >
                            Key Path: {item.keyPath}
                          </small>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              </div>

              {/* Right Column: Grounded Summary + Validation Gate + Searchable Registry Key Table */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                {/* Card 5: Evidence-Grounded Forensic Summary */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <Bot size={17} />5 · Evidence-Grounded Registry Summary
                    </h2>
                    <span className="ai-label">FACT vs. INTERPRETATION</span>
                  </div>

                  <div className="hash-item">
                    <div className="detail-label">
                      OBSERVED FACTS (DETERMINISTIC KEY/VALUE EXTRACTION)
                    </div>
                    <p style={{ fontSize: 11, lineHeight: 1.65 }}>
                      • <strong>Source Evidence:</strong>{' '}
                      <code className="mono">
                        {selectedEvidenceCode} ({activeFilename})
                      </code>
                      <br />• <strong>Format & Scope:</strong> {activeData.detectedFormat} —{' '}
                      <strong>{activeData.totalKeysCount}</strong> Registry keys and{' '}
                      <strong>{activeData.totalValuesCount}</strong> values parsed.
                      <br />• <strong>System Identity:</strong>{' '}
                      {activeData.productName || activeData.computerName
                        ? `${[
                            activeData.productName,
                            activeData.displayVersion,
                            activeData.computerName
                              ? `Host: ${activeData.computerName}`
                              : null,
                          ]
                            .filter(Boolean)
                            .join(' · ')}`
                        : 'Not Present'}
                      .<br />• <strong>Artifact Counts by Category:</strong> Persistence (
                      <code>Run/RunOnce</code>):{' '}
                      <strong>{activeData.persistenceEntries.length}</strong> · USB History (
                      <code>USBSTOR/MountedDevices</code>):{' '}
                      <strong>{activeData.usbEntries.length}</strong> · User Activity (
                      <code>TypedPaths/RunMRU/RecentDocs</code>):{' '}
                      <strong>{activeData.userActivityEntries.length}</strong>.
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
                            High-Priority Persistence / Forensic Indicators:{' '}
                          </strong>
                          {activeData.anomalies.join(' ')} Note that the presence of a{' '}
                          <code className="mono">Run</code> key proves configuration for
                          autostart, but does not by itself prove the referenced file still
                          exists on disk — correlate with filesystem and prefetch artifacts.
                        </>
                      ) : (
                        <>
                          Extracted Registry keys show standard configuration entries without
                          obvious temp-folder script persistence. Remember that{' '}
                          <code className="mono">.reg</code> text exports do not preserve binary
                          Registry key LastWrite timestamps unless exported as a raw{' '}
                          <code className="mono">regf</code> hive. Verify key paths using{' '}
                          <code className="mono">reg query</code> or Registry Explorer below.
                        </>
                      )}
                    </p>
                  </div>

                  {/* Quick Registry Reference Commands (Section 13) */}
                  <div className="verify-box" style={{ paddingTop: 10 }}>
                    <div className="detail-label">
                      <Terminal size={12} style={{ display: 'inline', marginRight: 5 }} />
                      SECTION 13 · WINDOWS REGISTRY VALIDATION COMMANDS
                    </div>
                    <div className="cmd-list">
                      {[
                        [
                          'OS Version',
                          'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" /v ProductName',
                        ],
                        [
                          'User Run Keys',
                          'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
                        ],
                        [
                          'USB History',
                          'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR" /s',
                        ],
                        [
                          'Export .REG',
                          'reg export "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" my_run_keys.reg /y',
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

                {/* Card 6: Independent Validation Gate for Registry */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <ShieldCheck size={17} />6 · Independent Registry Validation Gate
                    </h2>
                    <span className="subtle-label">LOG TO 9-COLUMN VALIDATION LOG</span>
                  </div>

                  <form className="form-stack" onSubmit={handleRegistryValidationSubmit}>
                    <div className="form-row">
                      <label className="field-label">
                        Independent Tool Used *
                        <select
                          value={independentTool}
                          onChange={e => setIndependentTool(e.target.value)}
                        >
                          {REGISTRY_INDEPENDENT_TOOLS.map(t => (
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
                            VERIFIED (Key paths & values match independent tool)
                          </option>
                          <option value="MISMATCH">
                            MISMATCH (Discrepancy between platform & tool)
                          </option>
                          <option value="NEEDS REVIEW">
                            NEEDS REVIEW (Suspicious persistence / partial hive)
                          </option>
                        </select>
                      </label>
                    </div>

                    <label className="field-label">
                      Confirmed Artifact #1 (OS / System Identity or Key Count) *
                      <input
                        required
                        value={valArtifact1}
                        onChange={e => setValArtifact1(e.target.value)}
                        className="mono"
                      />
                    </label>

                    <label className="field-label">
                      Confirmed Artifact #2 (Persistence / Run Key or Value) *
                      <input
                        required
                        value={valArtifact2}
                        onChange={e => setValArtifact2(e.target.value)}
                        className="mono"
                      />
                    </label>

                    <label className="field-label">
                      Confirmed Artifact #3 (USBSTOR / User Activity Key)
                      <input
                        value={valArtifact3}
                        onChange={e => setValArtifact3(e.target.value)}
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
                        Notes / Key Attribution Observations
                        <input
                          placeholder="e.g. Verified HKCU Run & USBSTOR keys with reg query / Registry Explorer"
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
                          : `Record Registry ${valStatus} in Validation Log`}
                      </Button>
                      <Button asChild variant="outline" type="button">
                        <Link to="/validation">
                          Open Validation Log
                          <ArrowUpRight size={14} />
                        </Link>
                      </Button>
                    </div>
                  </form>

                  {registryValidations.length > 0 && (
                    <div className="verify-box">
                      <div className="detail-label">
                        RECORDED REGISTRY VALIDATIONS FOR {selectedEvidenceCode} (
                        {registryValidations.length})
                      </div>
                      <div className="hash-list">
                        {registryValidations.map(v => (
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

                {/* Card 7: Complete Searchable Registry Key & Value Table */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <Layers size={17} />
                      Extracted Registry Keys & Source Attribution ({filteredTableEntries.length})
                    </h2>
                    {activeData.allEntries.length > 0 && (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          copyText(
                            'Registry JSON',
                            JSON.stringify(activeData.allEntries, null, 2),
                          )
                        }
                      >
                        <Copy size={12} />
                        Copy JSON
                      </Button>
                    )}
                  </div>

                  <div className="form-row">
                    <input
                      placeholder="Search key path, value name, or data…"
                      value={searchQuery}
                      onChange={e => setSearchQuery(e.target.value)}
                    />
                    <select
                      aria-label="Filter registry category"
                      value={tableCategoryFilter}
                      onChange={e => setTableCategoryFilter(e.target.value)}
                    >
                      <option value="all">All categories ({activeData.allEntries.length})</option>
                      <option value="system">OS & System Info</option>
                      <option value="persistence">
                        Persistence / Run ({activeData.persistenceEntries.length})
                      </option>
                      <option value="usb">
                        USB History ({activeData.usbEntries.length})
                      </option>
                      <option value="user_activity">
                        User Activity ({activeData.userActivityEntries.length})
                      </option>
                      <option value="other">Other Keys</option>
                    </select>
                  </div>

                  {filteredTableEntries.length > 0 ? (
                    <div className="table-wrap" style={{ maxHeight: 340, overflowY: 'auto' }}>
                      <table>
                        <thead>
                          <tr>
                            <th>REGISTRY KEY PATH (SOURCE REF)</th>
                            <th>VALUE NAME & TYPE</th>
                            <th>EXTRACTED DATA</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredTableEntries.map((item, idx) => (
                            <tr key={`${item.sourceRef}-${idx}`}>
                              <td className="mono" style={{ fontSize: 9, maxWidth: 230, wordBreak: 'break-all' }}>
                                {item.keyPath}
                                <small className="muted" style={{ display: 'block' }}>
                                  {item.rawLineOrOffset}
                                </small>
                              </td>
                              <td>
                                <strong>{item.valueName}</strong>
                                <small className="mono muted" style={{ display: 'block' }}>
                                  {item.valueType}
                                </small>
                              </td>
                              <td className="mono" style={{ fontSize: 10, wordBreak: 'break-all' }}>
                                {item.valueData}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="muted" style={{ fontSize: 11 }}>
                      No matching Registry entries for the current filter.
                    </p>
                  )}
                </section>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
