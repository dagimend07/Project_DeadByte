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
  Image as ImageIcon,
  Upload,
  Copy,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Archive,
  MapPin,
  Camera,
  Clock3,
  Terminal,
  ArrowUpRight,
  FileWarning,
  Bot,
  Layers,
} from 'lucide-react';

export interface ExtractedExifTag {
  ifd: string;
  tagIdHex: string;
  tagName: string;
  value: string;
  sourceRef: string;
}

export interface ParsedImageAnalysis {
  supported: boolean;
  corrupted: boolean;
  errorMessage?: string;
  detectedFormat: string;
  magicBytesHex: string;
  extensionName: string;
  extensionMismatch: boolean;
  mismatchReason?: string;
  width: number | null;
  height: number | null;
  bitDepth: string | null;
  colorSpace: string | null;
  compression: string | null;
  make: string | null;
  model: string | null;
  software: string | null;
  lensModel: string | null;
  serialNumber: string | null;
  artist: string | null;
  copyright: string | null;
  orientation: string | null;
  exposureTime: string | null;
  fNumber: string | null;
  iso: string | null;
  focalLength: string | null;
  flash: string | null;
  dateTimeOriginal: string | null;
  dateTimeDigitized: string | null;
  modifyDate: string | null;
  offsetTimeOriginal: string | null;
  gpsLatitudeDecimal: number | null;
  gpsLongitudeDecimal: number | null;
  gpsLatitudeDms: string | null;
  gpsLongitudeDms: string | null;
  gpsAltitude: string | null;
  gpsTimestamp: string | null;
  rawTags: ExtractedExifTag[];
  anomalies: string[];
}

const EXIF_INDEPENDENT_TOOLS = [
  'ExifTool (exiftool FILE)',
  'Autopsy Image Analyzer',
  'ImageMagick (identify -verbose)',
  'OS Inspector (Windows Properties / macOS Preview)',
  'Other Approved Metadata Tool',
] as const;

const IFD_TAG_NAMES: Record<number, string> = {
  0x0100: 'ImageWidth',
  0x0101: 'ImageHeight',
  0x0102: 'BitsPerSample',
  0x0103: 'Compression',
  0x010e: 'ImageDescription',
  0x010f: 'Make',
  0x0110: 'Model',
  0x0112: 'Orientation',
  0x011a: 'XResolution',
  0x011b: 'YResolution',
  0x0128: 'ResolutionUnit',
  0x0131: 'Software',
  0x0132: 'ModifyDate',
  0x013b: 'Artist',
  0x013c: 'HostComputer',
  0x8298: 'Copyright',
  0x829a: 'ExposureTime',
  0x829d: 'FNumber',
  0x8822: 'ExposureProgram',
  0x8827: 'ISO',
  0x9000: 'ExifVersion',
  0x9003: 'DateTimeOriginal',
  0x9004: 'CreateDate',
  0x9010: 'OffsetTime',
  0x9011: 'OffsetTimeOriginal',
  0x9201: 'ShutterSpeedValue',
  0x9202: 'ApertureValue',
  0x9204: 'ExposureBiasValue',
  0x9207: 'MeteringMode',
  0x9209: 'Flash',
  0x920a: 'FocalLength',
  0x9290: 'SubSecTime',
  0x9291: 'SubSecTimeOriginal',
  0xa001: 'ColorSpace',
  0xa002: 'ExifImageWidth',
  0xa003: 'ExifImageHeight',
  0xa405: 'FocalLengthIn35mmFormat',
  0xa431: 'SerialNumber',
  0xa432: 'LensInfo',
  0xa433: 'LensMake',
  0xa434: 'LensModel',
};

const GPS_TAG_NAMES: Record<number, string> = {
  0x0000: 'GPSVersionID',
  0x0001: 'GPSLatitudeRef',
  0x0002: 'GPSLatitude',
  0x0003: 'GPSLongitudeRef',
  0x0004: 'GPSLongitude',
  0x0005: 'GPSAltitudeRef',
  0x0006: 'GPSAltitude',
  0x0007: 'GPSTimeStamp',
  0x0010: 'GPSImgDirectionRef',
  0x0011: 'GPSImgDirection',
  0x0012: 'GPSMapDatum',
  0x001d: 'GPSDateStamp',
};

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

function parseTiffBlock(
  view: DataView,
  tiffStart: number,
  maxEnd: number,
  rawTags: ExtractedExifTag[],
): Record<string, string | number | number[]> {
  const result: Record<string, string | number | number[]> = {};
  if (tiffStart + 8 > maxEnd || tiffStart + 8 > view.byteLength) return result;

  const byteOrder = view.getUint16(tiffStart, false);
  const littleEndian = byteOrder === 0x4949;
  if (!littleEndian && byteOrder !== 0x4d4d) return result;

  const magic = view.getUint16(tiffStart + 2, littleEndian);
  if (magic !== 42) return result;

  const ifd0Offset = view.getUint32(tiffStart + 4, littleEndian);

  function readTagValue(
    type: number,
    count: number,
    valueOffsetFieldPos: number,
  ): string | number | number[] | null {
    const typeSizes: Record<number, number> = {
      1: 1, // BYTE
      2: 1, // ASCII
      3: 2, // SHORT
      4: 4, // LONG
      5: 8, // RATIONAL
      7: 1, // UNDEFINED
      9: 4, // SLONG
      10: 8, // SRATIONAL
    };
    const unitSize = typeSizes[type];
    if (!unitSize) return null;
    const totalBytes = unitSize * count;
    let dataPos = valueOffsetFieldPos;
    if (totalBytes > 4) {
      const relOffset = view.getUint32(valueOffsetFieldPos, littleEndian);
      dataPos = tiffStart + relOffset;
    }
    if (dataPos < 0 || dataPos + totalBytes > view.byteLength) return null;

    if (type === 2) {
      return readAscii(view, dataPos, count);
    }
    if (type === 7) {
      return readAscii(view, dataPos, Math.min(count, 64));
    }
    if (type === 1) {
      const arr: number[] = [];
      for (let i = 0; i < Math.min(count, 16); i++) {
        arr.push(view.getUint8(dataPos + i));
      }
      return count === 1 ? arr[0] : arr;
    }
    if (type === 3) {
      const arr: number[] = [];
      for (let i = 0; i < Math.min(count, 16); i++) {
        arr.push(view.getUint16(dataPos + i * 2, littleEndian));
      }
      return count === 1 ? arr[0] : arr;
    }
    if (type === 4) {
      const arr: number[] = [];
      for (let i = 0; i < Math.min(count, 16); i++) {
        arr.push(view.getUint32(dataPos + i * 4, littleEndian));
      }
      return count === 1 ? arr[0] : arr;
    }
    if (type === 9) {
      const arr: number[] = [];
      for (let i = 0; i < Math.min(count, 16); i++) {
        arr.push(view.getInt32(dataPos + i * 4, littleEndian));
      }
      return count === 1 ? arr[0] : arr;
    }
    if (type === 5 || type === 10) {
      const signed = type === 10;
      const arr: number[] = [];
      for (let i = 0; i < Math.min(count, 8); i++) {
        const num = signed
          ? view.getInt32(dataPos + i * 8, littleEndian)
          : view.getUint32(dataPos + i * 8, littleEndian);
        const den = signed
          ? view.getInt32(dataPos + i * 8 + 4, littleEndian)
          : view.getUint32(dataPos + i * 8 + 4, littleEndian);
        arr.push(den !== 0 ? num / den : 0);
      }
      if (count === 1) {
        const num = signed
          ? view.getInt32(dataPos, littleEndian)
          : view.getUint32(dataPos, littleEndian);
        const den = signed
          ? view.getInt32(dataPos + 4, littleEndian)
          : view.getUint32(dataPos + 4, littleEndian);
        if (den === 0) return 0;
        if (num < den && num > 0 && den <= 32000) {
          return `1/${Math.round(den / num)} (${(num / den).toFixed(4)})`;
        }
        return Number((num / den).toFixed(4));
      }
      return arr;
    }
    return null;
  }

  function parseIfd(ifdOffset: number, ifdName: string, isGps = false) {
    const dirStart = tiffStart + ifdOffset;
    if (dirStart + 2 > view.byteLength) return;
    const entryCount = view.getUint16(dirStart, littleEndian);
    if (entryCount > 500) return;

    for (let i = 0; i < entryCount; i++) {
      const entryPos = dirStart + 2 + i * 12;
      if (entryPos + 12 > view.byteLength) break;

      const tagId = view.getUint16(entryPos, littleEndian);
      const fieldType = view.getUint16(entryPos + 2, littleEndian);
      const count = view.getUint32(entryPos + 4, littleEndian);
      const valPos = entryPos + 8;

      if (!isGps && tagId === 0x8769) {
        const exifOffset = view.getUint32(valPos, littleEndian);
        parseIfd(exifOffset, 'ExifIFD', false);
        continue;
      }
      if (!isGps && tagId === 0x8825) {
        const gpsOffset = view.getUint32(valPos, littleEndian);
        parseIfd(gpsOffset, 'GPSIFD', true);
        continue;
      }

      const tagName = isGps
        ? GPS_TAG_NAMES[tagId] ?? `GPSTag_0x${tagId.toString(16).padStart(4, '0')}`
        : IFD_TAG_NAMES[tagId] ?? `Tag_0x${tagId.toString(16).padStart(4, '0')}`;
      const rawVal = readTagValue(fieldType, count, valPos);
      if (rawVal === null || rawVal === '') continue;

      result[tagName] = rawVal;
      const tagHex = `0x${tagId.toString(16).padStart(4, '0').toUpperCase()}`;
      const formattedVal = Array.isArray(rawVal) ? rawVal.join(', ') : String(rawVal);
      if (formattedVal.length > 0) {
        rawTags.push({
          ifd: ifdName,
          tagIdHex: tagHex,
          tagName,
          value: formattedVal,
          sourceRef: `${ifdName}:${tagHex} (${tagName})`,
        });
      }
    }
  }

  parseIfd(ifd0Offset, 'IFD0', false);
  return result;
}

function formatOrientation(val: string | number | number[] | undefined): string | null {
  if (val === undefined) return null;
  const n = Number(val);
  const map: Record<number, string> = {
    1: '1 · Horizontal (normal)',
    2: '2 · Mirror horizontal',
    3: '3 · Rotate 180°',
    4: '4 · Mirror vertical',
    5: '5 · Mirror horizontal & rotate 270° CW',
    6: '6 · Rotate 90° CW',
    7: '7 · Mirror horizontal & rotate 90° CW',
    8: '8 · Rotate 270° CW',
  };
  return map[n] ?? String(val);
}

function formatFlash(val: string | number | number[] | undefined): string | null {
  if (val === undefined) return null;
  const n = Number(val);
  if (Number.isNaN(n)) return String(val);
  return (n & 1) === 1 ? `Fired (0x${n.toString(16)})` : `Did not fire (0x${n.toString(16)})`;
}

function convertGpsToDmsAndDecimal(
  coords: string | number | number[] | undefined,
  ref: string | number | number[] | undefined,
): { decimal: number; dms: string } | null {
  if (!Array.isArray(coords) || coords.length < 3) return null;
  const [deg, min, sec] = coords.map(Number);
  if ([deg, min, sec].some(n => Number.isNaN(n))) return null;
  const refStr = String(ref || '').toUpperCase();
  let dec = deg + min / 60 + sec / 3600;
  if (refStr === 'S' || refStr === 'W') dec = -dec;
  const dms = `${Math.floor(deg)}° ${Math.floor(min)}' ${sec.toFixed(2)}" ${refStr || ''}`.trim();
  return { decimal: Number(dec.toFixed(6)), dms };
}

/**
 * Deterministic binary parser for JPEG, PNG, TIFF, and WebP images.
 * Checks magic bytes vs extension, extracts dimensions, EXIF, and GPS.
 */
export function parseImageEvidenceBuffer(
  buffer: ArrayBuffer,
  filename: string,
): ParsedImageAnalysis {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const extMatch = filename.toLowerCase().match(/\.([a-z0-9]+)$/);
  const ext = extMatch ? extMatch[1] : 'none';
  const magicHex = bytesToHex(bytes, 8);
  const rawTags: ExtractedExifTag[] = [];
  const anomalies: string[] = [];

  const base: ParsedImageAnalysis = {
    supported: false,
    corrupted: false,
    detectedFormat: 'Unknown Binary',
    magicBytesHex: magicHex,
    extensionName: `.${ext}`,
    extensionMismatch: false,
    width: null,
    height: null,
    bitDepth: null,
    colorSpace: null,
    compression: null,
    make: null,
    model: null,
    software: null,
    lensModel: null,
    serialNumber: null,
    artist: null,
    copyright: null,
    orientation: null,
    exposureTime: null,
    fNumber: null,
    iso: null,
    focalLength: null,
    flash: null,
    dateTimeOriginal: null,
    dateTimeDigitized: null,
    modifyDate: null,
    offsetTimeOriginal: null,
    gpsLatitudeDecimal: null,
    gpsLongitudeDecimal: null,
    gpsLatitudeDms: null,
    gpsLongitudeDms: null,
    gpsAltitude: null,
    gpsTimestamp: null,
    rawTags,
    anomalies,
  };

  if (bytes.length === 0) {
    return {
      ...base,
      corrupted: true,
      errorMessage: 'Empty file (0 bytes). Cannot extract image metadata.',
    };
  }

  // Detect true binary signature
  const isJpeg = bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  const isPng =
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a;
  const isTiff =
    bytes.length >= 4 &&
    ((bytes[0] === 0x49 && bytes[1] === 0x49 && bytes[2] === 0x2a && bytes[3] === 0x00) ||
      (bytes[0] === 0x4d && bytes[1] === 0x4d && bytes[2] === 0x00 && bytes[3] === 0x2a));
  const isWebp =
    bytes.length >= 12 &&
    readAscii(view, 0, 4) === 'RIFF' &&
    readAscii(view, 8, 4) === 'WEBP';
  const ftypBrand =
    bytes.length >= 12 && readAscii(view, 4, 4) === 'ftyp'
      ? readAscii(view, 8, 4).toLowerCase()
      : '';
  const isHeic =
    ftypBrand !== '' &&
    ['heic', 'heix', 'hevc', 'hevx', 'mif1', 'msf1', 'avif', 'avis'].includes(ftypBrand);

  if (isJpeg) {
    base.detectedFormat = 'JPEG (Joint Photographic Experts Group)';
    base.supported = true;
    if (!['jpg', 'jpeg', 'jpe', 'jfif'].includes(ext)) {
      base.extensionMismatch = true;
      base.mismatchReason = `File has extension ".${ext}", but binary signature (${magicHex}) is a JPEG image.`;
      anomalies.push(base.mismatchReason);
    }
  } else if (isPng) {
    base.detectedFormat = 'PNG (Portable Network Graphics)';
    base.supported = true;
    if (ext !== 'png') {
      base.extensionMismatch = true;
      base.mismatchReason = `File has extension ".${ext}", but binary signature (${magicHex}) is a PNG image.`;
      anomalies.push(base.mismatchReason);
    }
  } else if (isTiff) {
    base.detectedFormat = 'TIFF (Tagged Image File Format)';
    base.supported = true;
    if (!['tif', 'tiff'].includes(ext)) {
      base.extensionMismatch = true;
      base.mismatchReason = `File has extension ".${ext}", but binary signature (${magicHex}) is a TIFF image.`;
      anomalies.push(base.mismatchReason);
    }
  } else if (isWebp) {
    base.detectedFormat = 'WebP (RIFF WebP Image)';
    base.supported = true;
    if (ext !== 'webp') {
      base.extensionMismatch = true;
      base.mismatchReason = `File has extension ".${ext}", but binary signature (${magicHex}) is a WebP image.`;
      anomalies.push(base.mismatchReason);
    }
  } else if (isHeic) {
    base.detectedFormat = `Apple HEIC / HEIF Container (ftyp:${ftypBrand})`;
    base.compression = 'HEVC (H.265 High Efficiency Image Coding)';
    base.supported = true;
    if (!['heic', 'heif', 'avif', 'hif'].includes(ext)) {
      base.extensionMismatch = true;
      base.mismatchReason = `File has extension ".${ext}", but binary signature (${magicHex}) is an Apple HEIC/HEIF container (ftyp:${ftypBrand}).`;
      anomalies.push(base.mismatchReason);
    }
  } else {
    // Check if the filename claims to be an image (.jpg, .png, .tif, .webp, .heic) when binary signature is NOT!
    if (['jpg', 'jpeg', 'png', 'tif', 'tiff', 'webp', 'heic', 'heif'].includes(ext)) {
      base.extensionMismatch = true;
      base.mismatchReason = `RENAMED / SPOOFED EXTENSION: File is named ".${ext}", but its binary header (${magicHex}) is NOT a valid JPEG, PNG, TIFF, WebP, or HEIC header.`;
      anomalies.push(base.mismatchReason);
    }
    base.supported = false;
    base.errorMessage = base.extensionMismatch
      ? base.mismatchReason
      : `UNSUPPORTED FILE TYPE: Binary signature (${magicHex}) is not a supported image format (JPEG, PNG, TIFF, WebP, HEIC). No metadata was fabricated.`;
    return base;
  }

  let exifDict: Record<string, string | number | number[]> = {};

  try {
    if (isJpeg) {
      let offset = 2;
      let foundSof = false;
      while (offset + 4 <= bytes.length) {
        if (bytes[offset] !== 0xff) {
          offset++;
          continue;
        }
        const marker = bytes[offset + 1];
        if (marker === 0xd9 || marker === 0xda) break; // EOI or SOS
        if (marker === 0x00 || marker === 0xff) {
          offset++;
          continue;
        }
        const segLen = view.getUint16(offset + 2, false);
        if (segLen < 2 || offset + 2 + segLen > bytes.length) {
          base.corrupted = true;
          anomalies.push('Truncated JPEG segment detected before end of stream.');
          break;
        }

        // APP1 (EXIF)
        if (marker === 0xe1 && segLen >= 8) {
          const headerStr = readAscii(view, offset + 4, 4);
          if (headerStr === 'Exif') {
            const tiffStart = offset + 10;
            exifDict = {
              ...exifDict,
              ...parseTiffBlock(view, tiffStart, offset + 2 + segLen, rawTags),
            };
          }
        }

        // SOF0 / SOF1 / SOF2 (Dimensions & Bit Depth)
        if ([0xc0, 0xc1, 0xc2].includes(marker) && offset + 9 < bytes.length) {
          foundSof = true;
          const precision = view.getUint8(offset + 4);
          const h = view.getUint16(offset + 5, false);
          const w = view.getUint16(offset + 7, false);
          const components = view.getUint8(offset + 9);
          base.height = h;
          base.width = w;
          base.bitDepth = `${precision}-bit (${components} channels)`;
          base.compression = marker === 0xc2 ? 'JPEG Progressive (SOF2)' : 'JPEG Baseline (SOF0)';
          rawTags.push({
            ifd: 'JPEG:SOF',
            tagIdHex: `0xFF${marker.toString(16).toUpperCase()}`,
            tagName: 'SOF Frame Header',
            value: `${w}×${h} px, ${precision}-bit, ${components} components`,
            sourceRef: `JPEG:SOF@0x${offset.toString(16).toUpperCase()}`,
          });
        }

        offset += 2 + segLen;
      }
      if (!foundSof && !base.width && !exifDict['ExifImageWidth']) {
        base.corrupted = true;
        base.errorMessage =
          'CORRUPTED JPEG: Valid FF D8 FF header found, but JPEG frame header (SOF) is missing or truncated.';
      }
    } else if (isTiff) {
      exifDict = parseTiffBlock(view, 0, bytes.length, rawTags);
    } else if (isPng) {
      let offset = 8;
      while (offset + 8 <= bytes.length) {
        const chunkLen = view.getUint32(offset, false);
        const chunkType = readAscii(view, offset + 4, 4);
        const dataStart = offset + 8;
        if (dataStart + chunkLen + 4 > bytes.length) {
          base.corrupted = true;
          base.errorMessage = `CORRUPTED PNG: Chunk "${chunkType}" exceeds file length.`;
          break;
        }
        if (chunkType === 'IHDR' && chunkLen >= 13) {
          base.width = view.getUint32(dataStart, false);
          base.height = view.getUint32(dataStart + 4, false);
          const depth = view.getUint8(dataStart + 8);
          const colorType = view.getUint8(dataStart + 9);
          const colorMap: Record<number, string> = {
            0: 'Grayscale',
            2: 'RGB Truecolor',
            3: 'Indexed-color',
            4: 'Grayscale + Alpha',
            6: 'RGBA Truecolor + Alpha',
          };
          base.bitDepth = `${depth}-bit`;
          base.colorSpace = colorMap[colorType] ?? `PNG ColorType ${colorType}`;
          base.compression = 'Deflate (PNG IHDR)';
          rawTags.push({
            ifd: 'PNG:IHDR',
            tagIdHex: 'IHDR',
            tagName: 'ImageHeader',
            value: `${base.width}×${base.height} px, ${base.bitDepth}, ${base.colorSpace}`,
            sourceRef: `PNG:IHDR@0x${offset.toString(16).toUpperCase()}`,
          });
        } else if (chunkType === 'eXIf') {
          exifDict = {
            ...exifDict,
            ...parseTiffBlock(view, dataStart, dataStart + chunkLen, rawTags),
          };
        } else if (chunkType === 'tEXt' || chunkType === 'iTXt') {
          const textContent = readAscii(view, dataStart, Math.min(chunkLen, 256));
          if (textContent) {
            rawTags.push({
              ifd: `PNG:${chunkType}`,
              tagIdHex: chunkType,
              tagName: 'TextChunk',
              value: textContent,
              sourceRef: `PNG:${chunkType}@0x${offset.toString(16).toUpperCase()}`,
            });
            if (textContent.toLowerCase().startsWith('software')) {
              base.software = textContent.replace(/^software\s*/i, '');
            }
          }
        } else if (chunkType === 'tIME' && chunkLen >= 7) {
          const yr = view.getUint16(dataStart, false);
          const mo = String(view.getUint8(dataStart + 2)).padStart(2, '0');
          const da = String(view.getUint8(dataStart + 3)).padStart(2, '0');
          const hr = String(view.getUint8(dataStart + 4)).padStart(2, '0');
          const mi = String(view.getUint8(dataStart + 5)).padStart(2, '0');
          const se = String(view.getUint8(dataStart + 6)).padStart(2, '0');
          base.modifyDate = `${yr}:${mo}:${da} ${hr}:${mi}:${se} UTC`;
          rawTags.push({
            ifd: 'PNG:tIME',
            tagIdHex: 'tIME',
            tagName: 'LastModificationTime',
            value: base.modifyDate,
            sourceRef: `PNG:tIME@0x${offset.toString(16).toUpperCase()}`,
          });
        }
        if (chunkType === 'IEND') break;
        offset += 12 + chunkLen;
      }
    } else if (isWebp) {
      let offset = 12;
      while (offset + 8 <= bytes.length) {
        const chunkType = readAscii(view, offset, 4);
        const chunkLen = view.getUint32(offset + 4, true);
        const dataStart = offset + 8;
        if (dataStart + chunkLen > bytes.length) break;
        if (chunkType === 'VP8X' && chunkLen >= 10) {
          const w = 1 + (bytes[dataStart + 4] | (bytes[dataStart + 5] << 8) | (bytes[dataStart + 6] << 16));
          const h = 1 + (bytes[dataStart + 7] | (bytes[dataStart + 8] << 8) | (bytes[dataStart + 9] << 16));
          base.width = w;
          base.height = h;
          rawTags.push({
            ifd: 'WebP:VP8X',
            tagIdHex: 'VP8X',
            tagName: 'ExtendedHeader',
            value: `${w}×${h} px`,
            sourceRef: `WebP:VP8X@0x${offset.toString(16).toUpperCase()}`,
          });
        } else if (chunkType === 'EXIF') {
          const hasExifPrefix = readAscii(view, dataStart, 4) === 'Exif';
          const tiffStart = hasExifPrefix ? dataStart + 6 : dataStart;
          exifDict = {
            ...exifDict,
            ...parseTiffBlock(view, tiffStart, dataStart + chunkLen, rawTags),
          };
        }
        offset += 8 + chunkLen + (chunkLen % 2);
      }
    } else if (isHeic) {
      rawTags.push({
        ifd: 'ISOBMFF:ftyp',
        tagIdHex: 'ftyp',
        tagName: 'MajorBrand',
        value: ftypBrand,
        sourceRef: 'HEIC:ftyp@0x0004',
      });

      // 1. Scan ISO BMFF meta region for 'ispe' (Image Spatial Extents: Width & Height)
      const searchLimit = Math.min(bytes.length - 16, 512 * 1024);
      for (let i = 0; i < searchLimit; i++) {
        // 'i' 's' 'p' 'e' = 0x69 0x73 0x70 0x65
        if (
          bytes[i] === 0x69 &&
          bytes[i + 1] === 0x73 &&
          bytes[i + 2] === 0x70 &&
          bytes[i + 3] === 0x65 &&
          i >= 4
        ) {
          const boxSize = view.getUint32(i - 4, false);
          if (boxSize === 20 && i + 16 <= bytes.length) {
            const w = view.getUint32(i + 8, false);
            const h = view.getUint32(i + 12, false);
            if (w > 0 && w <= 65535 && h > 0 && h <= 65535) {
              if (!base.width || w > base.width) {
                base.width = w;
                base.height = h;
              }
              rawTags.push({
                ifd: 'HEIC:ispe',
                tagIdHex: 'ispe',
                tagName: 'ImageSpatialExtents',
                value: `${w}×${h} px`,
                sourceRef: `HEIC:ispe@0x${(i - 4).toString(16).toUpperCase()}`,
              });
            }
          }
        }
      }

      // 2. Scan HEIC binary stream for embedded Apple Exif TIFF block ("Exif\0\0" followed by "MM\0*" or "II*\0")
      for (let i = 0; i < bytes.length - 14; i++) {
        if (
          bytes[i] === 0x45 && // 'E'
          bytes[i + 1] === 0x78 && // 'x'
          bytes[i + 2] === 0x69 && // 'i'
          bytes[i + 3] === 0x66 && // 'f'
          bytes[i + 4] === 0x00 &&
          bytes[i + 5] === 0x00
        ) {
          const tiffStart = i + 6;
          const bo = view.getUint16(tiffStart, false);
          const check42 =
            bo === 0x4949
              ? view.getUint16(tiffStart + 2, true)
              : bo === 0x4d4d
                ? view.getUint16(tiffStart + 2, false)
                : 0;
          if (check42 === 42) {
            const parsedHeicExif = parseTiffBlock(view, tiffStart, bytes.length, rawTags);
            exifDict = { ...exifDict, ...parsedHeicExif };
            break;
          }
        }
      }
    }
  } catch (err) {
    base.corrupted = true;
    base.errorMessage =
      err instanceof Error
        ? `Parser caught malformed structure: ${err.message}`
        : 'Malformed binary structure encountered.';
  }

  // Populate structured fields from exifDict where present
  if (!base.width && (exifDict['ExifImageWidth'] || exifDict['ImageWidth'])) {
    base.width = Number(exifDict['ExifImageWidth'] ?? exifDict['ImageWidth']);
  }
  if (!base.height && (exifDict['ExifImageHeight'] || exifDict['ImageHeight'])) {
    base.height = Number(exifDict['ExifImageHeight'] ?? exifDict['ImageHeight']);
  }
  if (!base.colorSpace && exifDict['ColorSpace'] !== undefined) {
    base.colorSpace =
      Number(exifDict['ColorSpace']) === 1 ? 'sRGB (1)' : `ColorSpace (${exifDict['ColorSpace']})`;
  }
  if (exifDict['Make']) base.make = String(exifDict['Make']);
  if (exifDict['Model']) base.model = String(exifDict['Model']);
  if (exifDict['Software']) base.software = String(exifDict['Software']);
  if (exifDict['LensModel']) base.lensModel = String(exifDict['LensModel']);
  if (exifDict['SerialNumber']) base.serialNumber = String(exifDict['SerialNumber']);
  if (exifDict['Artist']) base.artist = String(exifDict['Artist']);
  if (exifDict['Copyright']) base.copyright = String(exifDict['Copyright']);
  base.orientation = formatOrientation(exifDict['Orientation']);
  if (exifDict['ExposureTime'] !== undefined)
    base.exposureTime = `${exifDict['ExposureTime']} sec`;
  if (exifDict['FNumber'] !== undefined) base.fNumber = `f/${exifDict['FNumber']}`;
  if (exifDict['ISO'] !== undefined) base.iso = `ISO ${exifDict['ISO']}`;
  if (exifDict['FocalLength'] !== undefined) base.focalLength = `${exifDict['FocalLength']} mm`;
  base.flash = formatFlash(exifDict['Flash']);

  if (exifDict['DateTimeOriginal']) base.dateTimeOriginal = String(exifDict['DateTimeOriginal']);
  if (exifDict['CreateDate']) base.dateTimeDigitized = String(exifDict['CreateDate']);
  if (exifDict['ModifyDate']) base.modifyDate = String(exifDict['ModifyDate']);
  if (exifDict['OffsetTimeOriginal'])
    base.offsetTimeOriginal = String(exifDict['OffsetTimeOriginal']);

  const latObj = convertGpsToDmsAndDecimal(exifDict['GPSLatitude'], exifDict['GPSLatitudeRef']);
  const lonObj = convertGpsToDmsAndDecimal(exifDict['GPSLongitude'], exifDict['GPSLongitudeRef']);
  if (latObj && lonObj) {
    base.gpsLatitudeDecimal = latObj.decimal;
    base.gpsLongitudeDecimal = lonObj.decimal;
    base.gpsLatitudeDms = latObj.dms;
    base.gpsLongitudeDms = lonObj.dms;
  }
  if (exifDict['GPSAltitude'] !== undefined) {
    const altRef = Number(exifDict['GPSAltitudeRef']) === 1 ? 'Below Sea Level' : 'Above Sea Level';
    base.gpsAltitude = `${exifDict['GPSAltitude']} m (${altRef})`;
  }
  if (exifDict['GPSDateStamp'] || exifDict['GPSTimeStamp']) {
    const d = exifDict['GPSDateStamp'] ? String(exifDict['GPSDateStamp']) : '';
    const tArr = Array.isArray(exifDict['GPSTimeStamp'])
      ? exifDict['GPSTimeStamp'].map(n => String(Math.floor(Number(n))).padStart(2, '0')).join(':')
      : '';
    base.gpsTimestamp = `${d} ${tArr} UTC`.trim();
  }

  // Forensic anomaly checks
  if (
    base.dateTimeOriginal &&
    base.modifyDate &&
    base.dateTimeOriginal !== base.modifyDate
  ) {
    anomalies.push(
      `Timestamp discrepancy: ModifyDate (${base.modifyDate}) differs from DateTimeOriginal (${base.dateTimeOriginal}).`,
    );
  }
  if (
    base.software &&
    /(photoshop|gimp|lightroom|canva|snapseed|affinity|paint|pixelmator|exiftool)/i.test(
      base.software,
    )
  ) {
    anomalies.push(
      `Editing software signature detected in IFD0:0x0131 (Software = "${base.software}").`,
    );
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

export function ExifAnalyzer() {
  const { user, cases, evidence, validations, refresh } = useWorkspace();

  const [mode, setMode] = useState<'evidence' | 'standalone'>('evidence');
  const [caseFilter, setCaseFilter] = useState('all');
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string>('');
  const [analysis, setAnalysis] = useState<ParsedImageAnalysis | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Standalone file state
  const [standaloneFile, setStandaloneFile] = useState<File | null>(null);
  const [standaloneAnalysis, setStandaloneAnalysis] = useState<ParsedImageAnalysis | null>(null);
  const [standalonePreviewUrl, setStandalonePreviewUrl] = useState<string | null>(null);
  const standaloneInputRef = useRef<HTMLInputElement>(null);

  // Independent Validation Gate state (Section 3, Module 3 & Section 9.2)
  const [independentTool, setIndependentTool] = useState<string>(EXIF_INDEPENDENT_TOOLS[0]);
  const [valField1, setValField1] = useState('');
  const [valField2, setValField2] = useState('');
  const [valField3, setValField3] = useState('');
  const [valStatus, setValStatus] = useState<'VERIFIED' | 'MISMATCH' | 'NEEDS REVIEW'>('VERIFIED');
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

  // Parse selected evidence item
  useEffect(() => {
    let cancelled = false;
    let objectUrlToRevoke: string | null = null;

    async function inspectEvidence() {
      if (!selectedEvidence) {
        setAnalysis(null);
        setPreviewUrl(null);
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
                'Original evidence binary not found in local IndexedDB. Switch to Standalone Image Inspector or re-upload the image.',
              detectedFormat: 'Unavailable',
              magicBytesHex: 'N/A',
              extensionName: selectedEvidence.filename,
              extensionMismatch: false,
              width: null,
              height: null,
              bitDepth: null,
              colorSpace: null,
              compression: null,
              make: null,
              model: null,
              software: null,
              lensModel: null,
              serialNumber: null,
              artist: null,
              copyright: null,
              orientation: null,
              exposureTime: null,
              fNumber: null,
              iso: null,
              focalLength: null,
              flash: null,
              dateTimeOriginal: null,
              dateTimeDigitized: null,
              modifyDate: null,
              offsetTimeOriginal: null,
              gpsLatitudeDecimal: null,
              gpsLongitudeDecimal: null,
              gpsLatitudeDms: null,
              gpsLongitudeDms: null,
              gpsAltitude: null,
              gpsTimestamp: null,
              rawTags: [],
              anomalies: [],
            });
            setPreviewUrl(null);
          }
          return;
        }

        const buffer = await blob.arrayBuffer();
        const parsed = parseImageEvidenceBuffer(buffer, selectedEvidence.filename);

        if (!cancelled) {
          setAnalysis(parsed);
          if (parsed.supported && !parsed.corrupted) {
            objectUrlToRevoke = URL.createObjectURL(blob);
            setPreviewUrl(objectUrlToRevoke);
            if (selectedEvidence.processing_status === 'UNPROCESSED') {
              if (markLocalEvidenceProcessed(selectedEvidence.id)) {
                await refresh();
              }
            }
          } else {
            setPreviewUrl(null);
          }

          // Pre-populate the 3 verification field suggestions from extracted facts
          const f1 = parsed.width && parsed.height
            ? `Dimensions: ${parsed.width}x${parsed.height} (${parsed.detectedFormat.split(' ')[0]})`
            : `Format: ${parsed.detectedFormat}`;
          const f2 = parsed.make || parsed.model
            ? `Device: ${[parsed.make, parsed.model].filter(Boolean).join(' ')}`
            : `Camera Make/Model: Not Present`;
          const f3 = parsed.dateTimeOriginal
            ? `DateTimeOriginal: ${parsed.dateTimeOriginal}`
            : parsed.gpsLatitudeDecimal !== null
              ? `GPS: ${parsed.gpsLatitudeDecimal}, ${parsed.gpsLongitudeDecimal}`
              : `DateTimeOriginal / GPS: Not Present`;
          setValField1(f1);
          setValField2(f2);
          setValField3(f3);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    inspectEvidence();
    return () => {
      cancelled = true;
      if (objectUrlToRevoke) URL.revokeObjectURL(objectUrlToRevoke);
    };
  }, [selectedEvidence?.id, user]);

  // Parse standalone dropped file
  useEffect(() => {
    let cancelled = false;
    let urlToRevoke: string | null = null;
    async function inspectStandalone() {
      if (!standaloneFile) {
        setStandaloneAnalysis(null);
        setStandalonePreviewUrl(null);
        return;
      }
      const buffer = await standaloneFile.arrayBuffer();
      const parsed = parseImageEvidenceBuffer(buffer, standaloneFile.name);
      if (!cancelled) {
        setStandaloneAnalysis(parsed);
        if (parsed.supported && !parsed.corrupted) {
          urlToRevoke = URL.createObjectURL(standaloneFile);
          setStandalonePreviewUrl(urlToRevoke);
        } else {
          setStandalonePreviewUrl(null);
        }
      }
    }
    inspectStandalone();
    return () => {
      cancelled = true;
      if (urlToRevoke) URL.revokeObjectURL(urlToRevoke);
    };
  }, [standaloneFile]);

  const activeData = mode === 'evidence' ? analysis : standaloneAnalysis;
  const activePreview = mode === 'evidence' ? previewUrl : standalonePreviewUrl;
  const activeFilename =
    mode === 'evidence'
      ? selectedEvidence?.filename ?? ''
      : standaloneFile?.name ?? '';
  const selectedEvidenceCode = selectedEvidence
    ? getEvidenceCode(selectedEvidence.id, evidence)
    : 'STANDALONE';
  const exifValidations = selectedEvidence
    ? validations.filter(v => v.evidence_id === selectedEvidence.id && v.module === 'EXIF')
    : [];

  async function copyText(label: string, text: string) {
    await navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard.`);
  }

  async function handleExifValidationSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!selectedEvidence || !analysis) return;
    const confirmedValues = [valField1.trim(), valField2.trim(), valField3.trim()].filter(
      Boolean,
    );
    if (confirmedValues.length < 3) {
      toast.error(
        'Rubric Section 4 requires confirming at least 3 metadata values (including "Not Present" if absent).',
      );
      return;
    }

    setSavingVal(true);
    try {
      const relatedCase = cases.find(c => c.id === selectedEvidence.case_id);
      const evCode = getEvidenceCode(selectedEvidence.id, evidence);
      const platformSummary = [
        analysis.width && analysis.height
          ? `${analysis.width}x${analysis.height}px`
          : analysis.detectedFormat.split(' ')[0],
        analysis.make || analysis.model
          ? [analysis.make, analysis.model].filter(Boolean).join(' ')
          : 'Device: Not Present',
        analysis.dateTimeOriginal
          ? `Original: ${analysis.dateTimeOriginal}`
          : 'Timestamp: Not Present',
      ].join(' | ');

      saveValidationRecord({
        case_id: selectedEvidence.case_id,
        case_number: relatedCase?.case_number ?? 'DB-LOCAL',
        evidence_id: selectedEvidence.id,
        evidence_code: evCode,
        filename: selectedEvidence.filename,
        module: 'EXIF',
        algorithm: 'Metadata (3+ fields)',
        platform_result: platformSummary,
        independent_tool: independentTool,
        independent_result: confirmedValues.join(' | '),
        status: valStatus,
        validator: validatorName.trim(),
        notes:
          validationNotes.trim() ||
          `Confirmed 3 metadata fields with ${independentTool}.`,
      });

      await refresh();
      setValidationNotes('');
      toast.success(
        `EXIF validation (${valStatus}) recorded for ${evCode} in Validation Log.`,
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not save EXIF validation.');
    } finally {
      setSavingVal(false);
    }
  }

  return (
    <div className="hash-analyzer">
      {/* Top Mode Bar */}
      <div className="analyzer-controls">
        <div className="mode-tabs" role="tablist" aria-label="EXIF analyzer mode">
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'evidence'}
            className={`mode-tab ${mode === 'evidence' ? 'active' : ''}`}
            onClick={() => setMode('evidence')}
          >
            <Archive size={15} />
            <span>Inspect Evidence Locker Image</span>
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
            <span>Standalone Image Inspector</span>
          </button>
        </div>

        <div className="algo-bar">
          <span className="detail-label" style={{ marginBottom: 0 }}>
            SUPPORTED FORMATS:
          </span>
          <span className="algo-tag">JPEG / JPG</span>
          <span className="algo-tag">HEIC / iPhone</span>
          <span className="algo-tag">PNG</span>
          <span className="algo-tag">TIFF</span>
          <span className="algo-tag">WebP</span>
        </div>
      </div>

      {/* Selector Bar */}
      {mode === 'evidence' ? (
        evidence.length === 0 ? (
          <Empty
            icon={ImageIcon}
            title="No evidence files in your locker yet"
            description="Upload an image in the Evidence Locker to inspect its EXIF metadata, or switch to Standalone Image Inspector to drop any image from your computer."
          >
            <div style={{ display: 'flex', gap: 10 }}>
              <Button asChild variant="outline" size="sm">
                <Link to="/evidence">
                  Open Evidence Locker
                  <ArrowUpRight />
                </Link>
              </Button>
              <Button variant="default" size="sm" onClick={() => setMode('standalone')}>
                <ImageIcon size={14} />
                Use Standalone Image Inspector
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
            <Button
              type="button"
              variant="outline"
              onClick={() => standaloneInputRef.current?.click()}
            >
              Choose image or test file from computer
            </Button>
            <p>
              {standaloneFile
                ? `${standaloneFile.name} · ${(standaloneFile.size / 1024).toFixed(2)} KB`
                : 'Drop JPEG, PNG, TIFF, WebP (or renamed/unsupported test file) here'}
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

      {/* Main Analysis Output */}
      {loading && (
        <div className="analyzer-card">
          <p className="mono muted">Parsing binary header and IFD metadata tables…</p>
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
                    ? 'UNSUPPORTED OR SPOOFED FILE FORMAT DETECTED'
                    : activeData.corrupted
                      ? 'CORRUPTED / TRUNCATED IMAGE EVIDENCE DETECTED'
                      : 'FILE EXTENSION vs. BINARY SIGNATURE MISMATCH'}
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
              {/* Left Column: Extracted Metadata Categories */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                {/* Card 1: Image Preview & File Signature */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <ImageIcon size={17} />1 · Binary Signature & Image Properties
                    </h2>
                    <span className="algo-tag">
                      {selectedEvidenceCode} · {activeFilename}
                    </span>
                  </div>

                  {activePreview && (
                    <div className="exif-preview-box">
                      <img src={activePreview} alt={activeFilename} />
                    </div>
                  )}

                  <div className="exif-fields-grid">
                    <FieldRow
                      label="DETECTED FORMAT (MAGIC BYTES)"
                      value={activeData.detectedFormat}
                      sourceRef={`Header: ${activeData.magicBytesHex}`}
                    />
                    <FieldRow
                      label="EXTENSION vs. SIGNATURE CHECK"
                      value={
                        activeData.extensionMismatch
                          ? `MISMATCH (${activeData.extensionName})`
                          : `VALID (${activeData.extensionName} matches header)`
                      }
                      mono
                    />
                    <FieldRow
                      label="DIMENSIONS (WIDTH × HEIGHT)"
                      value={
                        activeData.width && activeData.height
                          ? `${activeData.width} × ${activeData.height} px (${(
                              (activeData.width * activeData.height) /
                              1_000_000
                            ).toFixed(2)} MP)`
                          : null
                      }
                      sourceRef="Frame/IFD"
                      mono
                    />
                    <FieldRow
                      label="COLOR SPACE / BIT DEPTH"
                      value={
                        [activeData.colorSpace, activeData.bitDepth]
                          .filter(Boolean)
                          .join(' · ') || null
                      }
                      sourceRef="0xA001 / SOF"
                    />
                    <FieldRow
                      label="COMPRESSION"
                      value={activeData.compression}
                      sourceRef="Header"
                    />
                    <FieldRow
                      label="ORIENTATION"
                      value={activeData.orientation}
                      sourceRef="IFD0:0x0112"
                    />
                  </div>
                </section>

                {/* Card 2: Camera, Device & Software Provenance */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <Camera size={17} />2 · Camera, Device & Software Metadata
                    </h2>
                    <span className="subtle-label">DETERMINISTIC PARSER</span>
                  </div>

                  <div className="exif-fields-grid">
                    <FieldRow
                      label="CAMERA / DEVICE MAKE"
                      value={activeData.make}
                      sourceRef="IFD0:0x010F"
                    />
                    <FieldRow
                      label="CAMERA / DEVICE MODEL"
                      value={activeData.model}
                      sourceRef="IFD0:0x0110"
                    />
                    <FieldRow
                      label="SOFTWARE / FIRMWARE"
                      value={activeData.software}
                      sourceRef="IFD0:0x0131"
                    />
                    <FieldRow
                      label="LENS MODEL"
                      value={activeData.lensModel}
                      sourceRef="ExifIFD:0xA434"
                    />
                    <FieldRow
                      label="DEVICE SERIAL NUMBER"
                      value={activeData.serialNumber}
                      sourceRef="ExifIFD:0xA431"
                      mono
                    />
                    <FieldRow
                      label="ARTIST / AUTHOR"
                      value={activeData.artist}
                      sourceRef="IFD0:0x013B"
                    />
                    <FieldRow
                      label="EXPOSURE TIME (SHUTTER)"
                      value={activeData.exposureTime}
                      sourceRef="ExifIFD:0x829A"
                      mono
                    />
                    <FieldRow
                      label="APERTURE (F-NUMBER)"
                      value={activeData.fNumber}
                      sourceRef="ExifIFD:0x829D"
                      mono
                    />
                    <FieldRow
                      label="ISO SPEED RATING"
                      value={activeData.iso}
                      sourceRef="ExifIFD:0x8827"
                      mono
                    />
                    <FieldRow
                      label="FOCAL LENGTH"
                      value={activeData.focalLength}
                      sourceRef="ExifIFD:0x920A"
                      mono
                    />
                    <FieldRow
                      label="FLASH STATUS"
                      value={activeData.flash}
                      sourceRef="ExifIFD:0x9209"
                    />
                    <FieldRow
                      label="COPYRIGHT"
                      value={activeData.copyright}
                      sourceRef="IFD0:0x8298"
                    />
                  </div>
                </section>

                {/* Card 3: Timestamps & Geolocation (GPS) */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <Clock3 size={17} />3 · Forensic Timestamps & GPS Geolocation
                    </h2>
                  </div>

                  <div className="exif-fields-grid">
                    <FieldRow
                      label="DATETIME ORIGINAL (CAPTURE)"
                      value={activeData.dateTimeOriginal}
                      sourceRef="ExifIFD:0x9003"
                      mono
                    />
                    <FieldRow
                      label="CREATE / DIGITIZED DATE"
                      value={activeData.dateTimeDigitized}
                      sourceRef="ExifIFD:0x9004"
                      mono
                    />
                    <FieldRow
                      label="MODIFY DATE (FILE / SOFTWARE)"
                      value={activeData.modifyDate}
                      sourceRef="IFD0:0x0132"
                      mono
                    />
                    <FieldRow
                      label="TIMEZONE OFFSET"
                      value={activeData.offsetTimeOriginal}
                      sourceRef="ExifIFD:0x9011"
                      mono
                    />
                    <FieldRow
                      label="GPS LATITUDE"
                      value={
                        activeData.gpsLatitudeDecimal !== null
                          ? `${activeData.gpsLatitudeDms} (${activeData.gpsLatitudeDecimal})`
                          : null
                      }
                      sourceRef="GPSIFD:0x0002"
                      mono
                    />
                    <FieldRow
                      label="GPS LONGITUDE"
                      value={
                        activeData.gpsLongitudeDecimal !== null
                          ? `${activeData.gpsLongitudeDms} (${activeData.gpsLongitudeDecimal})`
                          : null
                      }
                      sourceRef="GPSIFD:0x0004"
                      mono
                    />
                    <FieldRow
                      label="GPS ALTITUDE"
                      value={activeData.gpsAltitude}
                      sourceRef="GPSIFD:0x0006"
                      mono
                    />
                    <FieldRow
                      label="GPS UTC TIMESTAMP"
                      value={activeData.gpsTimestamp}
                      sourceRef="GPSIFD:0x001D/0x0007"
                      mono
                    />
                  </div>

                  {activeData.gpsLatitudeDecimal !== null &&
                    activeData.gpsLongitudeDecimal !== null && (
                      <div className="integrity-banner match" style={{ marginTop: 8 }}>
                        <MapPin size={20} />
                        <div style={{ flex: 1 }}>
                          <strong>GEOLOCATION COORDINATES PRESENT</strong>
                          <p className="mono">
                            {activeData.gpsLatitudeDecimal}, {activeData.gpsLongitudeDecimal} (
                            {activeData.gpsLatitudeDms}, {activeData.gpsLongitudeDms})
                          </p>
                          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              onClick={() =>
                                copyText(
                                  'GPS Coordinates',
                                  `${activeData.gpsLatitudeDecimal}, ${activeData.gpsLongitudeDecimal}`,
                                )
                              }
                            >
                              <Copy size={12} />
                              Copy Decimal GPS
                            </Button>
                            <Button asChild size="sm" variant="default">
                              <a
                                href={`https://www.openstreetmap.org/?mlat=${activeData.gpsLatitudeDecimal}&mlon=${activeData.gpsLongitudeDecimal}#map=16/${activeData.gpsLatitudeDecimal}/${activeData.gpsLongitudeDecimal}`}
                                target="_blank"
                                rel="noreferrer"
                              >
                                <MapPin size={12} />
                                Open in OpenStreetMap
                                <ArrowUpRight size={12} />
                              </a>
                            </Button>
                          </div>
                        </div>
                      </div>
                    )}
                </section>
              </div>

              {/* Right Column: Grounded AI Interpretation + Independent Validation Gate + Raw Tags */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                {/* Grounded AI Interpretation Card (Prompt 4 & Section 4.2) */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <Bot size={17} />4 · Evidence-Grounded Forensic Summary
                    </h2>
                    <span className="ai-label">FACT vs. INTERPRETATION</span>
                  </div>

                  <div className="hash-item">
                    <div className="detail-label">OBSERVED FACTS (FROM BINARY & IFD TAGS)</div>
                    <p style={{ fontSize: 11, lineHeight: 1.65 }}>
                      • <strong>Source Evidence:</strong>{' '}
                      <code className="mono">
                        {selectedEvidenceCode} ({activeFilename})
                      </code>
                      <br />• <strong>Binary Format:</strong> {activeData.detectedFormat} (Header:{' '}
                      <code className="mono">{activeData.magicBytesHex}</code>), Dimensions:{' '}
                      {activeData.width && activeData.height
                        ? `${activeData.width}×${activeData.height} px`
                        : 'Not Present'}
                      .<br />• <strong>Extracted IFD Tags:</strong> {activeData.rawTags.length}{' '}
                      structured tags recovered. Device:{' '}
                      {activeData.make || activeData.model
                        ? `${[activeData.make, activeData.model].filter(Boolean).join(' ')} (IFD0:0x010F/0x0110)`
                        : 'Not Present'}
                      . Original Capture Timestamp:{' '}
                      {activeData.dateTimeOriginal
                        ? `${activeData.dateTimeOriginal} (ExifIFD:0x9003)`
                        : 'Not Present'}
                      . GPS:{' '}
                      {activeData.gpsLatitudeDecimal !== null
                        ? `${activeData.gpsLatitudeDecimal}, ${activeData.gpsLongitudeDecimal} (GPSIFD:0x0002/0x0004)`
                        : 'Not Present'}
                      .
                    </p>
                  </div>

                  <div className="hash-item">
                    <div className="detail-label">
                      AI COPILOT INTERPRETATION & UNCERTAINTY (UNVERIFIED UNTIL HUMAN CHECK)
                    </div>
                    <p style={{ fontSize: 11, lineHeight: 1.65, color: 'var(--muted-foreground)' }}>
                      {activeData.anomalies.length > 0 ? (
                        <>
                          <strong style={{ color: 'var(--amber)' }}>
                            Forensic Indicators Observed:{' '}
                          </strong>
                          {activeData.anomalies.join(' ')}
                        </>
                      ) : activeData.rawTags.length <= 2 ? (
                        <>
                          This image contains minimal or stripped EXIF metadata (Camera, Capture
                          Timestamps, and GPS are <strong>Not Present</strong>). In forensic
                          investigations, absent EXIF commonly occurs when an image has been
                          transmitted through messaging/social platforms, exported for the web, or
                          captured with metadata stripping enabled. No missing values have been
                          inferred.
                        </>
                      ) : (
                        <>
                          Embedded camera provenance and timestamps are present. Remember that EXIF
                          timestamps depend on the device’s internal clock setting at the time of
                          capture and can be modified by software tools. Correlate{' '}
                          <code className="mono">ExifIFD:0x9003</code> with filesystem or network
                          artifacts before drawing timeline conclusions.
                        </>
                      )}
                    </p>
                  </div>

                  {/* Quick ExifTool Reference Commands (Section 13) */}
                  <div className="verify-box" style={{ paddingTop: 10 }}>
                    <div className="detail-label">
                      <Terminal size={12} style={{ display: 'inline', marginRight: 5 }} />
                      SECTION 13 · EXIFTOOL INDEPENDENT VALIDATION COMMANDS
                    </div>
                    <div className="cmd-list">
                      {[
                        ['All EXIF', `exiftool "${activeFilename}"`],
                        ['Grouped + Hex IDs', `exiftool -a -u -g1 -H "${activeFilename}"`],
                        ['GPS & Timestamps', `exiftool -gps:all -time:all "${activeFilename}"`],
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

                {/* Independent Validation Gate for EXIF (Section 4 Acceptance Test: confirm at least 3 values) */}
                {mode === 'evidence' && selectedEvidence && (
                  <section className="analyzer-card">
                    <div className="section-title" style={{ paddingTop: 0 }}>
                      <h2>
                        <ShieldCheck size={17} />5 · Independent EXIF Validation Gate
                      </h2>
                      <span className="subtle-label">CONFIRM 3+ VALUES (SECTION 4)</span>
                    </div>

                    <form className="form-stack" onSubmit={handleExifValidationSubmit}>
                      <div className="form-row">
                        <label className="field-label">
                          Independent Tool Used *
                          <select
                            value={independentTool}
                            onChange={e => setIndependentTool(e.target.value)}
                          >
                            {EXIF_INDEPENDENT_TOOLS.map(t => (
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
                              VERIFIED (Independent tool confirms 3+ values)
                            </option>
                            <option value="MISMATCH">
                              MISMATCH (Discrepancy between platform & tool)
                            </option>
                            <option value="NEEDS REVIEW">
                              NEEDS REVIEW (Ambiguous / stripped / timezone issue)
                            </option>
                          </select>
                        </label>
                      </div>

                      <label className="field-label">
                        Confirmed Value #1 (e.g. Format / Dimensions) *
                        <input
                          required
                          value={valField1}
                          onChange={e => setValField1(e.target.value)}
                          className="mono"
                        />
                      </label>

                      <label className="field-label">
                        Confirmed Value #2 (e.g. Camera Make / Model / Software) *
                        <input
                          required
                          value={valField2}
                          onChange={e => setValField2(e.target.value)}
                          className="mono"
                        />
                      </label>

                      <label className="field-label">
                        Confirmed Value #3 (e.g. DateTimeOriginal / GPS) *
                        <input
                          required
                          value={valField3}
                          onChange={e => setValField3(e.target.value)}
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
                          Notes / Timezone Assumptions
                          <input
                            placeholder="e.g. Verified with exiftool v12.96"
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
                            : `Record EXIF ${valStatus} in Validation Log`}
                        </Button>
                        <Button asChild variant="outline" type="button">
                          <Link to="/validation">
                            Open Validation Log
                            <ArrowUpRight size={14} />
                          </Link>
                        </Button>
                      </div>
                    </form>

                    {exifValidations.length > 0 && (
                      <div className="verify-box">
                        <div className="detail-label">
                          RECORDED EXIF VALIDATIONS FOR {selectedEvidenceCode} (
                          {exifValidations.length})
                        </div>
                        <div className="hash-list">
                          {exifValidations.map(v => (
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
                )}

                {/* Card 6: Raw Extracted Tags Table with Source References */}
                <section className="analyzer-card">
                  <div className="section-title" style={{ paddingTop: 0 }}>
                    <h2>
                      <Layers size={17} />
                      Raw Extracted Tags & Source References ({activeData.rawTags.length})
                    </h2>
                    {activeData.rawTags.length > 0 && (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          copyText(
                            'EXIF JSON',
                            JSON.stringify(activeData.rawTags, null, 2),
                          )
                        }
                      >
                        <Copy size={12} />
                        Copy JSON
                      </Button>
                    )}
                  </div>

                  {activeData.rawTags.length > 0 ? (
                    <div className="table-wrap" style={{ maxHeight: 320, overflowY: 'auto' }}>
                      <table>
                        <thead>
                          <tr>
                            <th>SOURCE REFERENCE</th>
                            <th>TAG NAME</th>
                            <th>EXTRACTED VALUE</th>
                          </tr>
                        </thead>
                        <tbody>
                          {activeData.rawTags.map((t, idx) => (
                            <tr key={`${t.sourceRef}-${idx}`}>
                              <td className="mono" style={{ fontSize: 9 }}>
                                {t.ifd}:{t.tagIdHex}
                              </td>
                              <td>
                                <strong>{t.tagName}</strong>
                              </td>
                              <td className="mono" style={{ fontSize: 10 }}>
                                {t.value}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="muted" style={{ fontSize: 11 }}>
                      No optional IFD/EXIF tags present in this image beyond the base container
                      header.
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
