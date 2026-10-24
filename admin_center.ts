import express, { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import net from 'net';
import type { DownloadStatRecord, SupportedPlatform } from './server.js';

// ==================== TYPES & INTERFACES ====================

export type AdminRole = 'owner' | 'admin' | 'viewer';

export interface AdminUser {
  id: string;
  username: string;
  email: string;
  role: AdminRole;
  password_hash: string; // format: scrypt$N$r$p$saltHex$derivedHex
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
  disabled: boolean;
}

export interface AdminSession {
  sid_hash: string;
  user_id: string;
  username: string;
  role: AdminRole;
  csrf_token: string;
  created_at: number;
  expires_at: number;
  last_active_at: number;
  user_agent_summary: string;
}

export type ContactInquiryStatus = 'open' | 'in_progress' | 'resolved' | 'spam';

export interface ContactTimelineEntry {
  timestamp: string;
  action: string;
  actor: string;
  detail?: string;
}

export interface ContactInquiryState {
  inquiry_id: string;
  read: boolean;
  status: ContactInquiryStatus;
  issue_type: 'inquiry' | 'feedback' | 'bug_report' | 'other';
  admin_notes: string;
  email_notification_status: 'not_configured' | 'sent' | 'failed' | 'pending';
  email_notification_at: string | null;
  email_notification_error: string | null;
  updated_at: string;
  timeline: ContactTimelineEntry[];
}

export interface RawContactRecord {
  inquiry_id: string;
  timestamp: string;
  category: string;
  platform: string;
  name: string;
  email: string;
  message: string;
}

export type ContactFunnelEventType =
  | 'form_opened'
  | 'validation_failed'
  | 'submission_attempted'
  | 'submission_stored'
  | 'email_sent'
  | 'email_failed';

export interface ContactFunnelEvent {
  timestamp: string;
  event_id: string;
  event_type: ContactFunnelEventType;
  category?: string;
  platform?: string;
  reason?: string;
  inquiry_id?: string;
}

export interface VisitorTelemetryEvent {
  timestamp: string;
  event_type: 'page_view' | 'link_submit' | 'download_click' | 'contact_open';
  path: string;
  referrer_host: string;
  device_category: 'desktop' | 'mobile' | 'tablet';
  lang: string;
  platform?: string;
  visitor_id?: string;
  session_id?: string;
  ip_address?: string;
  ip_version?: 'IPv4' | 'IPv6' | 'unknown';
}

export type ActivityEventCategory =
  | 'navigation'
  | 'link_submission'
  | 'download_lifecycle'
  | 'ui_interaction'
  | 'modal_interaction'
  | 'settings'
  | 'contact'
  | 'admin';

export type ActivityEventType =
  | 'page_view'
  | 'platform_select'
  | 'url_focus'
  | 'url_paste'
  | 'link_submitted'
  | 'link_validated'
  | 'unsupported_url'
  | 'invalid_url'
  | 'quality_select'
  | 'format_select'
  | 'download_requested'
  | 'processing'
  | 'upstream_retrieved'
  | 'stream_started'
  | 'download_succeeded'
  | 'download_client_completed'
  | 'download_failed'
  | 'cancelled'
  | 'timed_out'
  | 'retry'
  | 'settings_modal_open'
  | 'cookie_saved'
  | 'cookie_cleared'
  | 'contact_modal_open'
  | 'upgrade_modal_open'
  | 'help_guide_open'
  | 'faq_modal_open'
  | 'blog_modal_open';

export type ActivityEventStatus =
  | 'info'
  | 'valid'
  | 'invalid'
  | 'unsupported'
  | 'processing'
  | 'stream_started'
  | 'success'
  | 'failed'
  | 'cancelled'
  | 'timed_out';

export type DownloadLifecycleStage =
  | '1_request_processed'
  | '2_upstream_retrieved'
  | '3_stream_started'
  | '4_client_completed';

export interface ActivityEventRecord {
  event_id: string;
  timestamp: string;
  visitor_id: string;
  session_id: string;
  ip_address: string;
  ip_version: 'IPv4' | 'IPv6' | 'unknown';
  ip_hash: string;
  event_category: ActivityEventCategory;
  event_type: ActivityEventType;
  status: ActivityEventStatus;
  platform: string;
  normalized_hostname: string;
  valid_url: boolean | null;
  download_initiated: boolean;
  download_stage?: DownloadLifecycleStage;
  request_id: string;
  download_method?: string;
  quality?: string;
  format?: string;
  http_status?: number;
  error_category?: string | null;
  duration_ms?: number;
  bytes_transferred?: number;
  user_agent_summary: string;
  device_category: 'desktop' | 'mobile' | 'tablet';
  detail?: string;
}

export interface VisitorIpHistoryEntry {
  ip: string;
  ip_version: 'IPv4' | 'IPv6' | 'unknown';
  first_seen: string;
  last_seen: string;
  count: number;
}

export interface VisitorProfileRecord {
  visitor_id: string;
  account_type: 'anonymous_visitor' | 'admin_account';
  username?: string;
  email?: string;
  first_seen_at: string;
  last_active_at: string;
  session_count: number;
  last_session_id: string;
  links_submitted: number;
  valid_links_count: number;
  invalid_links_count: number;
  download_attempts: number;
  successful_downloads: number;
  client_confirmed_downloads: number;
  failed_downloads: number;
  cancelled_downloads: number;
  platform_counts: Record<string, number>;
  most_used_platform: string;
  last_activity_type: string;
  last_activity_status: string;
  last_ip: string;
  ip_version: 'IPv4' | 'IPv6' | 'unknown';
  ip_hash: string;
  ip_history: VisitorIpHistoryEntry[];
  user_agent_summary: string;
  device_category: 'desktop' | 'mobile' | 'tablet';
  blocked: boolean;
  rate_limit_override_rpm: number | null;
  admin_notes: string;
}

export interface UpgradePricingConfig {
  enabled: boolean;
  badge_text: string;
  headline_en: string;
  headline_zh: string;
  subheadline_en: string;
  subheadline_zh: string;
  free_plan: {
    name_en: string;
    name_zh: string;
    price_label: string;
    status_badge_en: string;
    status_badge_zh: string;
    features_en: string[];
    features_zh: string[];
  };
  pro_plan: {
    name_en: string;
    name_zh: string;
    price_label: string;
    status_badge_en: string;
    status_badge_zh: string;
    coming_soon: boolean;
    features_en: string[];
    features_zh: string[];
    cta_label_en: string;
    cta_label_zh: string;
  };
  contact_cta_enabled: boolean;
  updated_at: string;
}

export interface AppErrorRecord {
  timestamp: string;
  event_id: string;
  request_id: string;
  severity: 'warn' | 'error' | 'critical';
  route_category: 'parse' | 'download' | 'proxy' | 'zip' | 'contact' | 'admin' | 'system';
  platform: string;
  http_status: number;
  error_category: string;
  duration_ms: number;
  summary: string;
}

export interface AuditLogRecord {
  timestamp: string;
  audit_id: string;
  actor: string;
  action: string;
  target: string;
  ip_hash: string;
  status: 'success' | 'failed' | 'warning';
  detail: string;
}

export interface EmailDeliveryRecord {
  timestamp: string;
  delivery_id: string;
  event_type: 'contact_inquiry' | 'feedback' | 'error_alert' | 'repeated_failure_alert' | 'summary_report' | 'test_email';
  recipient: string;
  subject: string;
  status: 'sent' | 'failed' | 'skipped_not_configured';
  provider_id?: string;
  attempts: number;
  error?: string;
}

export interface AdminSettings {
  notification_to_email: string;
  notification_from_email: string;
  admin_alert_email: string;
  notify_on_contact: boolean;
  notify_on_feedback: boolean;
  notify_on_app_errors: boolean;
  notify_on_repeated_failures: boolean;
  repeated_failure_threshold: number;
  summary_schedule: 'off' | 'daily' | 'weekly';
  shortcut_enabled: boolean;
  shortcut_phrase_hash: string | null;
  shortcut_updated_at: string | null;
  ga4_measurement_id: string;
  ga4_property_id: string;
  gsc_site_url: string;
  retention_days_operational_logs: number;
  retention_days_contact_messages: number;
  session_ttl_hours: number;
  ip_logging_mode: 'full' | 'masked' | 'hashed';
  pricing_config?: UpgradePricingConfig;
  updated_at: string;
}

export interface BackupRecord {
  backup_id: string;
  filename: string;
  created_at: string;
  size_bytes: number;
  created_by: string;
}

// ==================== CONSTANTS & SCRYPT PASSWORD HASHING ====================

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;
const ADMIN_COOKIE_NAME = 'dd_admin_sid';
const VISITOR_COOKIE_NAME = 'dd_vid';
const VISITOR_SESSION_COOKIE_NAME = 'dd_sid';

export function hashPasswordScrypt(plainPassword: string): string {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(Buffer.from(plainPassword, 'utf8'), salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 32 * 1024 * 1024
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('hex')}$${derived.toString('hex')}`;
}

export function verifyPasswordScrypt(plainPassword: string, storedHash: string): boolean {
  try {
    const parts = (storedHash || '').split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const N = parseInt(parts[1], 10);
    const r = parseInt(parts[2], 10);
    const p = parseInt(parts[3], 10);
    const salt = Buffer.from(parts[4], 'hex');
    const expected = Buffer.from(parts[5], 'hex');
    if (!N || !r || !p || salt.length < 8 || expected.length !== SCRYPT_KEYLEN) return false;
    const actual = crypto.scryptSync(Buffer.from(plainPassword, 'utf8'), salt, expected.length, {
      N,
      r,
      p,
      maxmem: 64 * 1024 * 1024
    });
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

export function sha256Hex(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

export function timingSafeHexEqual(aHex: string, bHex: string): boolean {
  try {
    if (!aHex || !bHex || aHex.length !== bHex.length) return false;
    const a = Buffer.from(aHex, 'utf8');
    const b = Buffer.from(bHex, 'utf8');
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// ==================== TRUSTED PROXY IP EXTRACTION & NORMALIZATION ====================

function normalizeRawIp(raw?: string): string {
  if (!raw) return '';
  let s = String(raw).trim();
  if (!s || s === 'unknown') return '';
  // Strip port from IPv4:port if present (e.g. "1.2.3.4:5678")
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(s)) {
    s = s.split(':')[0];
  }
  // Strip brackets from [IPv6]:port
  if (s.startsWith('[')) {
    const closeIdx = s.indexOf(']');
    if (closeIdx > 1) s = s.slice(1, closeIdx);
  }
  // Unwrap IPv4-mapped IPv6 address (::ffff:a.b.c.d)
  if (s.toLowerCase().startsWith('::ffff:')) {
    const v4Candidate = s.slice(7);
    if (net.isIP(v4Candidate) === 4) {
      return v4Candidate;
    }
  }
  return s;
}

function isLoopbackOrPrivateProxyIp(ip: string): boolean {
  const clean = normalizeRawIp(ip);
  if (!clean) return false;
  if (clean === '127.0.0.1' || clean === '::1') return true;
  const trustedEnv = (process.env.TRUSTED_PROXY_IPS || '')
    .split(',')
    .map(x => normalizeRawIp(x))
    .filter(Boolean);
  if (trustedEnv.includes(clean)) return true;

  if (net.isIP(clean) === 4) {
    const parts = clean.split('.').map(n => parseInt(n, 10));
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  }
  if (net.isIP(clean) === 6) {
    const lower = clean.toLowerCase();
    if (lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80:')) {
      return true;
    }
  }
  return false;
}

export interface ClientIpInfo {
  ip_address: string;
  ip_version: 'IPv4' | 'IPv6' | 'unknown';
  ip_hash: string;
  trusted_proxy: boolean;
}

export function extractClientIpInfo(req: Request, mode: 'full' | 'masked' | 'hashed' = 'full'): ClientIpInfo {
  const socketIp = normalizeRawIp(req.socket?.remoteAddress || '');
  const trustedProxy = isLoopbackOrPrivateProxyIp(socketIp);

  let effectiveIp = socketIp;
  if (trustedProxy) {
    // Only trust X-Forwarded-For / X-Real-IP / CF-Connecting-IP when request arrives via a trusted reverse proxy
    const xff = String(req.headers['x-forwarded-for'] || '').trim();
    const xRealIp = String(req.headers['x-real-ip'] || '').trim();
    const cfIp = String(req.headers['cf-connecting-ip'] || '').trim();

    if (cfIp && net.isIP(normalizeRawIp(cfIp)) !== 0) {
      effectiveIp = normalizeRawIp(cfIp);
    } else if (xff) {
      const chain = xff.split(',').map(part => normalizeRawIp(part)).filter(ip => net.isIP(ip) !== 0);
      if (chain.length > 0) {
        effectiveIp = chain[0];
      }
    } else if (xRealIp && net.isIP(normalizeRawIp(xRealIp)) !== 0) {
      effectiveIp = normalizeRawIp(xRealIp);
    }
  }

  const ipVerNum = net.isIP(effectiveIp);
  const ipVersion: 'IPv4' | 'IPv6' | 'unknown' =
    ipVerNum === 4 ? 'IPv4' : ipVerNum === 6 ? 'IPv6' : 'unknown';

  const ipHash = effectiveIp
    ? 'ip_' + crypto.createHash('sha256').update('dd_ip_salt_v1:' + effectiveIp).digest('hex').slice(0, 12)
    : 'ip_unknown';

  let formattedIp = effectiveIp || 'unknown';
  if (mode === 'hashed') {
    formattedIp = ipHash;
  } else if (mode === 'masked' && effectiveIp) {
    if (ipVersion === 'IPv4') {
      const octets = effectiveIp.split('.');
      formattedIp = octets.length === 4 ? `${octets[0]}.${octets[1]}.${octets[2]}.xxx` : ipHash;
    } else if (ipVersion === 'IPv6') {
      const hextets = effectiveIp.split(':').filter(Boolean);
      formattedIp = hextets.slice(0, 3).join(':') + '::xxxx';
    }
  }

  return {
    ip_address: formattedIp,
    ip_version: ipVersion,
    ip_hash: ipHash,
    trusted_proxy: trustedProxy
  };
}

function hashClientIp(req: Request): string {
  return extractClientIpInfo(req, 'hashed').ip_hash;
}

export function extractNormalizedHostAndPath(rawInput: string): {
  normalized_hostname: string;
  valid_url: boolean;
} {
  if (!rawInput || typeof rawInput !== 'string') {
    return { normalized_hostname: 'empty', valid_url: false };
  }
  const trimmed = rawInput.trim();
  const urlMatch = trimmed.match(/https?:\/\/[^\s"'<>]+/i);
  const candidate = urlMatch ? urlMatch[0] : trimmed;
  try {
    const parsed = new URL(candidate.startsWith('http') ? candidate : `https://${candidate}`);
    if (!parsed.hostname || !parsed.hostname.includes('.')) {
      return { normalized_hostname: 'invalid-host', valid_url: false };
    }
    const host = parsed.hostname.toLowerCase().slice(0, 64);
    // Keep only first 2 path segments without query parameters or tokens
    const cleanSegments = parsed.pathname
      .split('/')
      .filter(Boolean)
      .slice(0, 2)
      .map(seg => seg.replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 24));
    const pathPreview = cleanSegments.length > 0 ? '/' + cleanSegments.join('/') : '';
    return {
      normalized_hostname: `${host}${pathPreview}`,
      valid_url: true
    };
  } catch {
    if (/^BV[a-zA-Z0-9]{10}$/i.test(trimmed) || /^av\d+$/i.test(trimmed)) {
      return { normalized_hostname: `bilibili.com/${trimmed.slice(0, 14)}`, valid_url: true };
    }
    if (/^\d{15,25}$/.test(trimmed)) {
      return { normalized_hostname: 'numeric-id-input', valid_url: false };
    }
    return { normalized_hostname: 'invalid-url', valid_url: false };
  }
}

function summarizeUserAgent(uaRaw?: string): string {
  const ua = String(uaRaw || '').slice(0, 180);
  if (!ua) return 'Unknown Browser';
  const browser =
    ua.includes('Edg/') ? 'Edge' :
    ua.includes('Chrome/') ? 'Chrome' :
    ua.includes('Firefox/') ? 'Firefox' :
    ua.includes('Safari/') ? 'Safari' : 'Browser';
  const osName =
    ua.includes('Windows') ? 'Windows' :
    ua.includes('Mac OS X') ? 'macOS' :
    ua.includes('Android') ? 'Android' :
    ua.includes('iPhone') || ua.includes('iPad') ? 'iOS' :
    ua.includes('Linux') ? 'Linux' : 'OS';
  return `${browser} on ${osName}`;
}

function detectDeviceCategory(uaRaw?: string): 'desktop' | 'mobile' | 'tablet' {
  const ua = String(uaRaw || '').toLowerCase();
  if (/ipad|tablet|playbook|silk/i.test(ua)) return 'tablet';
  if (/mobile|iphone|ipod|android.*mobile|windows phone/i.test(ua)) return 'mobile';
  return 'desktop';
}

function sanitizeLogSummary(raw: string): string {
  if (!raw) return 'Operation error';
  return String(raw)
    .replace(/https?:\/\/[^\s"'<>]+/gi, '[redacted-url]')
    .replace(/\/(?:var|home|app|tmp|usr|etc)\/[^\s"'<>]+/gi, '[redacted-path]')
    .replace(/(?:Bearer|SESSDATA|token|key|password|secret)[=:\s]+[^\s&"']+/gi, '[redacted-secret]')
    .replace(/[\r\n\t]+/g, ' ')
    .trim()
    .slice(0, 220);
}

function parseCookies(cookieHeader?: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) {
      try {
        out[k] = decodeURIComponent(v);
      } catch {
        out[k] = v;
      }
    }
  }
  return out;
}

// ==================== DEFAULT UPGRADE & PRICING CONFIG ====================

export const DEFAULT_PRICING_CONFIG: UpgradePricingConfig = {
  enabled: true,
  badge_text: 'PLANS & HD CAPABILITIES',
  headline_en: 'DownDouyin Plans & Capabilities',
  headline_zh: 'DownDouyin 套餐与高清解析能力',
  subheadline_en: 'All core watermark-free parsing and downloads are 100% free. Optional high-volume API tiers are coming soon.',
  subheadline_zh: '基础无水印解析与下载功能永久免费开放，高频批量 API 套餐即将推出。',
  free_plan: {
    name_en: 'Standard Web Downloader',
    name_zh: '标准网页版（当前使用）',
    price_label: '$0 / Free Forever',
    status_badge_en: 'Active Now',
    status_badge_zh: '当前已激活',
    features_en: [
      'Watermark-free Douyin, TikTok, Bilibili & Xiaohongshu parsing',
      'Up to 1080P / 4K Bilibili DASH & Douyin multi-CDN failover',
      'Live Photo & Multi-Photo Album ZIP batch packaging',
      'Custom SESSDATA & Proxy configuration in HD Settings'
    ],
    features_zh: [
      '支持抖音、TikTok、B站、小红书无水印视频与图文解析',
      '支持 B站 1080P/4K DASH 与抖音多节点容灾高速下载',
      '支持实况图 (Live Photo) 与多图图集一键打包 ZIP',
      '支持在「高清设置」中配置自定义 SESSDATA 与代理'
    ]
  },
  pro_plan: {
    name_en: 'Pro Batch & Developer API',
    name_zh: '专业批量版 & 开发者 API',
    price_label: 'Coming Soon',
    status_badge_en: 'Paid Plans Not Yet Available',
    status_badge_zh: '付费计划暂未开放',
    coming_soon: true,
    features_en: [
      'Automated creator profile & playlist bulk archiving',
      'Dedicated high-concurrency REST API keys & webhooks',
      'Server-side cloud muxing for 4K/8K Bilibili streams',
      'Priority enterprise support & SLA guarantees'
    ],
    features_zh: [
      '支持主页作品与收藏夹全量批量归档下载',
      '专属高并发 REST API 密钥与 Webhook 回调',
      '云端自动音视频封装合并（4K/8K 免本地混流）',
      '优先技术支持与企业级 SLA 稳定性保障'
    ],
    cta_label_en: 'Configure Free 1080P/4K Cookie Now',
    cta_label_zh: '立即免费配置 1080P/4K 高清 Cookie'
  },
  contact_cta_enabled: true,
  updated_at: new Date().toISOString()
};

// ==================== ADMIN CENTER CONTROLLER ====================

export interface AdminCenterDependencies {
  projectRoot: string;
  staticDir: string;
  logsDir: string;
  getDownloadStats: () => {
    recent: DownloadStatRecord[];
    summary: any;
  };
  getRuntimeConfigStatus: () => {
    bilibiliConfigured: boolean;
    bilibiliSource: string;
    tiktokProxyConfigured: boolean;
  };
}

export function setupAdminControlCenter(app: express.Express, deps: AdminCenterDependencies) {
  const { projectRoot, staticDir, logsDir } = deps;
  const backupsDir = path.join(logsDir, 'backups');

  const USERS_FILE = path.join(logsDir, 'admin-users.json');
  const SESSIONS_FILE = path.join(logsDir, 'admin-sessions.json');
  const SETTINGS_FILE = path.join(logsDir, 'admin-settings.json');
  const SETUP_TOKEN_FILE = path.join(logsDir, 'admin-setup-token.txt');
  const CONTACT_LOG_FILE = path.join(logsDir, 'contact-messages.jsonl');
  const CONTACT_STATE_FILE = path.join(logsDir, 'contact-state.json');
  const CONTACT_FUNNEL_FILE = path.join(logsDir, 'contact-events.jsonl');
  const VISITOR_LOG_FILE = path.join(logsDir, 'visitor-events.jsonl');
  const ACTIVITY_LOG_FILE = path.join(logsDir, 'activity-events.jsonl');
  const VISITORS_INDEX_FILE = path.join(logsDir, 'visitors-index.json');
  const ERRORS_LOG_FILE = path.join(logsDir, 'app-errors.jsonl');
  const AUDIT_LOG_FILE = path.join(logsDir, 'audit-log.jsonl');
  const EMAIL_LOG_FILE = path.join(logsDir, 'email-deliveries.jsonl');
  const STATS_LOG_FILE = path.join(logsDir, 'download-stats.jsonl');

  const serverStartTime = Date.now();

  try {
    fs.mkdirSync(logsDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(backupsDir, { recursive: true, mode: 0o700 });
  } catch {}

  // ---------------- 1. Persistent JSON / JSONL Helpers ----------------

  function readJsonFileSafe<T>(filePath: string, fallback: T): T {
    try {
      if (!fs.existsSync(filePath)) return fallback;
      const raw = fs.readFileSync(filePath, 'utf8');
      if (!raw.trim()) return fallback;
      return JSON.parse(raw) as T;
    } catch {
      return fallback;
    }
  }

  function writeJsonFileAtomic(filePath: string, data: unknown): void {
    try {
      fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
      const tmpPath = `${filePath}.tmp.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2, 6)}`;
      fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), { encoding: 'utf8', mode: 0o600 });
      fs.renameSync(tmpPath, filePath);
    } catch {}
  }

  function readJsonlTail<T>(filePath: string, maxLines = 5000, maxBytes = 4 * 1024 * 1024): T[] {
    const results: T[] = [];
    try {
      if (!fs.existsSync(filePath)) return results;
      const st = fs.statSync(filePath);
      if (!st.isFile() || st.size <= 0) return results;

      let content = '';
      if (st.size > maxBytes) {
        const fd = fs.openSync(filePath, 'r');
        try {
          const buf = Buffer.alloc(maxBytes);
          const bytesRead = fs.readSync(fd, buf, 0, maxBytes, st.size - maxBytes);
          content = buf.toString('utf8', 0, bytesRead);
          const firstNl = content.indexOf('\n');
          if (firstNl >= 0) content = content.slice(firstNl + 1);
        } finally {
          fs.closeSync(fd);
        }
      } else {
        content = fs.readFileSync(filePath, 'utf8');
      }

      const lines = content.split(/\r?\n/);
      const start = Math.max(0, lines.length - maxLines);
      for (let i = start; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        try {
          results.push(JSON.parse(line) as T);
        } catch {}
      }
    } catch {}
    return results;
  }

  function appendJsonlSafe(filePath: string, record: unknown, maxFileSizeBytes = 10 * 1024 * 1024): void {
    try {
      fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
      if (fs.existsSync(filePath)) {
        const st = fs.statSync(filePath);
        if (st.size > maxFileSizeBytes) {
          const keepBytes = Math.floor(maxFileSizeBytes * 0.6);
          const fd = fs.openSync(filePath, 'r');
          try {
            const buf = Buffer.alloc(keepBytes);
            const bytesRead = fs.readSync(fd, buf, 0, keepBytes, st.size - keepBytes);
            let tail = buf.toString('utf8', 0, bytesRead);
            const firstNl = tail.indexOf('\n');
            if (firstNl >= 0) tail = tail.slice(firstNl + 1);
            fs.writeFileSync(filePath, tail, { encoding: 'utf8', mode: 0o600 });
          } finally {
            fs.closeSync(fd);
          }
        }
      }
      fs.appendFileSync(filePath, JSON.stringify(record) + '\n', { encoding: 'utf8', mode: 0o600 });
    } catch {}
  }

  // ---------------- 2. Settings Management ----------------

  const defaultSettings: AdminSettings = {
    notification_to_email: process.env.CONTACT_TO_EMAIL || '',
    notification_from_email: process.env.CONTACT_FROM_EMAIL || 'DownDouyin Admin <onboarding@resend.dev>',
    admin_alert_email: process.env.ADMIN_ALERT_EMAIL || process.env.CONTACT_TO_EMAIL || '',
    notify_on_contact: true,
    notify_on_feedback: true,
    notify_on_app_errors: true,
    notify_on_repeated_failures: true,
    repeated_failure_threshold: 5,
    summary_schedule: 'off',
    shortcut_enabled: false,
    shortcut_phrase_hash: process.env.ADMIN_SHORTCUT_PHRASE
      ? sha256Hex(process.env.ADMIN_SHORTCUT_PHRASE.trim())
      : null,
    shortcut_updated_at: null,
    ga4_measurement_id: process.env.GA4_MEASUREMENT_ID || 'G-S9BHCYX6EN',
    ga4_property_id: process.env.GA4_PROPERTY_ID || '',
    gsc_site_url: process.env.GSC_SITE_URL || 'https://downdouyin.com/',
    retention_days_operational_logs: 90,
    retention_days_contact_messages: 365,
    session_ttl_hours: 12,
    ip_logging_mode: 'full',
    pricing_config: DEFAULT_PRICING_CONFIG,
    updated_at: new Date().toISOString()
  };

  let adminSettings: AdminSettings = {
    ...defaultSettings,
    ...readJsonFileSafe<Partial<AdminSettings>>(SETTINGS_FILE, {})
  };
  if (!adminSettings.pricing_config) {
    adminSettings.pricing_config = { ...DEFAULT_PRICING_CONFIG };
  }
  if (process.env.ADMIN_SHORTCUT_PHRASE && !adminSettings.shortcut_phrase_hash) {
    adminSettings.shortcut_phrase_hash = sha256Hex(process.env.ADMIN_SHORTCUT_PHRASE.trim());
    adminSettings.shortcut_enabled = true;
  }

  function saveAdminSettings(): void {
    adminSettings.updated_at = new Date().toISOString();
    writeJsonFileAtomic(SETTINGS_FILE, adminSettings);
  }

  // ---------------- 3. Audit Log ----------------

  function recordAuditLog(params: {
    actor: string;
    action: string;
    target: string;
    req?: Request;
    status: 'success' | 'failed' | 'warning';
    detail: string;
  }): void {
    const entry: AuditLogRecord = {
      timestamp: new Date().toISOString(),
      audit_id: 'aud_' + crypto.randomBytes(6).toString('hex'),
      actor: params.actor || 'system',
      action: params.action,
      target: params.target,
      ip_hash: params.req ? hashClientIp(params.req) : 'system',
      status: params.status,
      detail: sanitizeLogSummary(params.detail)
    };
    appendJsonlSafe(AUDIT_LOG_FILE, entry, 5 * 1024 * 1024);
  }

  // ---------------- 4. Visitor Profiles & Activity Log Engine ----------------

  const visitorsMap = new Map<string, VisitorProfileRecord>();
  const MAX_VISITOR_PROFILES = 5000;
  let visitorsDirty = false;
  let lastVisitorsSaveMs = 0;

  function loadVisitorsIndex(): void {
    const stored = readJsonFileSafe<VisitorProfileRecord[]>(VISITORS_INDEX_FILE, []);
    if (Array.isArray(stored)) {
      for (const v of stored) {
        if (v && typeof v.visitor_id === 'string' && v.visitor_id) {
          visitorsMap.set(v.visitor_id, v);
        }
      }
    }
  }
  loadVisitorsIndex();

  function saveVisitorsIndex(force = false): void {
    const now = Date.now();
    if (!force && (!visitorsDirty || now - lastVisitorsSaveMs < 2500)) return;
    visitorsDirty = false;
    lastVisitorsSaveMs = now;
    const all = Array.from(visitorsMap.values());
    all.sort((a, b) => b.last_active_at.localeCompare(a.last_active_at));
    writeJsonFileAtomic(VISITORS_INDEX_FILE, all.slice(0, MAX_VISITOR_PROFILES));
  }

  // Periodic flush for visitor profiles
  setInterval(() => {
    if (visitorsDirty) saveVisitorsIndex(true);
  }, 10000).unref?.();

  interface VisitorContext {
    visitor_id: string;
    session_id: string;
    ip_address: string;
    ip_version: 'IPv4' | 'IPv6' | 'unknown';
    ip_hash: string;
    user_agent_summary: string;
    device_category: 'desktop' | 'mobile' | 'tablet';
    is_new_session: boolean;
  }

  function resolveVisitorContext(req: Request, res?: Response, explicitIds?: { visitor_id?: string; session_id?: string }): VisitorContext {
    const cookies = parseCookies(req.headers.cookie);
    const ipInfo = extractClientIpInfo(req, adminSettings.ip_logging_mode || 'full');
    const uaSummary = summarizeUserAgent(req.headers['user-agent']);
    const deviceCat = detectDeviceCategory(req.headers['user-agent']);

    const sanitizeId = (raw?: string) =>
      typeof raw === 'string' ? raw.trim().replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 40) : '';

    let vid = sanitizeId(explicitIds?.visitor_id) || sanitizeId(cookies[VISITOR_COOKIE_NAME]) || sanitizeId(String(req.headers['x-visitor-id'] || ''));
    let sid = sanitizeId(explicitIds?.session_id) || sanitizeId(cookies[VISITOR_SESSION_COOKIE_NAME]) || sanitizeId(String(req.headers['x-session-id'] || ''));

    let isNewSession = false;
    if (!vid || !vid.startsWith('vid_')) {
      // Deterministic fallback by IP hash + UA within the same day if cookies aren't sent yet, or generate fresh cookie
      if (res && !res.headersSent) {
        vid = 'vid_' + crypto.randomBytes(8).toString('hex');
      } else {
        vid = 'vid_' + sha256Hex(`${ipInfo.ip_hash}:${uaSummary}`).slice(0, 16);
      }
    }
    if (!sid || !sid.startsWith('sid_')) {
      isNewSession = true;
      if (res && !res.headersSent) {
        sid = 'sid_' + crypto.randomBytes(6).toString('hex');
      } else {
        const halfHourBucket = Math.floor(Date.now() / (30 * 60 * 1000));
        sid = 'sid_' + sha256Hex(`${vid}:${halfHourBucket}`).slice(0, 12);
      }
    }

    if (res && !res.headersSent) {
      const existingSetCookie = res.getHeader('Set-Cookie');
      const cookieList: string[] = Array.isArray(existingSetCookie)
        ? existingSetCookie.map(String)
        : existingSetCookie
        ? [String(existingSetCookie)]
        : [];

      if (!cookies[VISITOR_COOKIE_NAME]) {
        cookieList.push(`${VISITOR_COOKIE_NAME}=${encodeURIComponent(vid)}; Path=/; SameSite=Lax; Max-Age=${180 * 24 * 3600}`);
      }
      if (!cookies[VISITOR_SESSION_COOKIE_NAME]) {
        cookieList.push(`${VISITOR_SESSION_COOKIE_NAME}=${encodeURIComponent(sid)}; Path=/; SameSite=Lax; Max-Age=1800`);
      }
      if (cookieList.length > 0) {
        res.setHeader('Set-Cookie', cookieList);
      }
    }

    return {
      visitor_id: vid,
      session_id: sid,
      ip_address: ipInfo.ip_address,
      ip_version: ipInfo.ip_version,
      ip_hash: ipInfo.ip_hash,
      user_agent_summary: uaSummary,
      device_category: deviceCat,
      is_new_session: isNewSession
    };
  }

  function isVisitorBlocked(req: Request): { blocked: boolean; reason?: string } {
    const ctx = resolveVisitorContext(req);
    const byId = visitorsMap.get(ctx.visitor_id);
    if (byId && byId.blocked) {
      return { blocked: true, reason: 'Visitor ID is blocked by administrator policy.' };
    }
    for (const v of visitorsMap.values()) {
      if (v.blocked && v.ip_hash === ctx.ip_hash && ctx.ip_hash !== 'ip_unknown') {
        return { blocked: true, reason: 'IP address is blocked by administrator policy.' };
      }
    }
    return { blocked: false };
  }

  // Deduplication map for rapid duplicate events: key -> timestampMs
  const recentEventDedupMap = new Map<string, number>();

  function shouldDeduplicateEvent(dedupKey: string, windowMs = 2500): boolean {
    const now = Date.now();
    const prev = recentEventDedupMap.get(dedupKey);
    if (prev && now - prev < windowMs) {
      return true;
    }
    recentEventDedupMap.set(dedupKey, now);
    if (recentEventDedupMap.size > 4000) {
      for (const [k, ts] of recentEventDedupMap.entries()) {
        if (now - ts > 15000) recentEventDedupMap.delete(k);
      }
    }
    return false;
  }

  function updateVisitorProfileFromEvent(ctx: VisitorContext, ev: ActivityEventRecord): void {
    const nowIso = ev.timestamp;
    let profile = visitorsMap.get(ctx.visitor_id);

    if (!profile) {
      profile = {
        visitor_id: ctx.visitor_id,
        account_type: 'anonymous_visitor',
        first_seen_at: nowIso,
        last_active_at: nowIso,
        session_count: 1,
        last_session_id: ctx.session_id,
        links_submitted: 0,
        valid_links_count: 0,
        invalid_links_count: 0,
        download_attempts: 0,
        successful_downloads: 0,
        client_confirmed_downloads: 0,
        failed_downloads: 0,
        cancelled_downloads: 0,
        platform_counts: { douyin: 0, bilibili: 0, tiktok: 0, xiaohongshu: 0 },
        most_used_platform: 'none',
        last_activity_type: ev.event_type,
        last_activity_status: ev.status,
        last_ip: ctx.ip_address,
        ip_version: ctx.ip_version,
        ip_hash: ctx.ip_hash,
        ip_history: [
          {
            ip: ctx.ip_address,
            ip_version: ctx.ip_version,
            first_seen: nowIso,
            last_seen: nowIso,
            count: 1
          }
        ],
        user_agent_summary: ctx.user_agent_summary,
        device_category: ctx.device_category,
        blocked: false,
        rate_limit_override_rpm: null,
        admin_notes: ''
      };
      visitorsMap.set(ctx.visitor_id, profile);
      if (visitorsMap.size > MAX_VISITOR_PROFILES + 200) {
        const oldestKey = visitorsMap.keys().next().value;
        if (oldestKey) visitorsMap.delete(oldestKey);
      }
    } else {
      profile.last_active_at = nowIso;
      if (profile.last_session_id !== ctx.session_id) {
        profile.session_count = (profile.session_count || 1) + 1;
        profile.last_session_id = ctx.session_id;
      }
      profile.last_activity_type = ev.event_type;
      profile.last_activity_status = ev.status;
      profile.last_ip = ctx.ip_address;
      profile.ip_version = ctx.ip_version;
      profile.ip_hash = ctx.ip_hash;
      profile.user_agent_summary = ctx.user_agent_summary;
      profile.device_category = ctx.device_category;

      const existingIpEntry = profile.ip_history.find(h => h.ip === ctx.ip_address);
      if (existingIpEntry) {
        existingIpEntry.last_seen = nowIso;
        existingIpEntry.count++;
      } else {
        profile.ip_history.unshift({
          ip: ctx.ip_address,
          ip_version: ctx.ip_version,
          first_seen: nowIso,
          last_seen: nowIso,
          count: 1
        });
        if (profile.ip_history.length > 15) {
          profile.ip_history = profile.ip_history.slice(0, 15);
        }
      }
    }

    // Increment counters accurately without double-counting stages
    if (ev.event_type === 'link_submitted' || ev.event_type === 'link_validated' || ev.event_type === 'unsupported_url' || ev.event_type === 'invalid_url') {
      if (ev.event_type === 'link_validated') {
        profile.links_submitted++;
        profile.valid_links_count++;
      } else if (ev.event_type === 'unsupported_url' || ev.event_type === 'invalid_url') {
        profile.links_submitted++;
        profile.invalid_links_count++;
      }
    } else if (ev.event_type === 'download_requested') {
      profile.download_attempts++;
    } else if (ev.event_type === 'download_succeeded') {
      profile.successful_downloads++;
    } else if (ev.event_type === 'download_client_completed') {
      profile.client_confirmed_downloads = (profile.client_confirmed_downloads || 0) + 1;
    } else if (ev.event_type === 'download_failed' || ev.event_type === 'timed_out') {
      profile.failed_downloads++;
    } else if (ev.event_type === 'cancelled') {
      profile.cancelled_downloads = (profile.cancelled_downloads || 0) + 1;
    }

    const plat = (ev.platform || '').toLowerCase();
    if (plat === 'douyin' || plat === 'bilibili' || plat === 'tiktok' || plat === 'xiaohongshu') {
      if (ev.event_type === 'link_validated' || ev.event_type === 'download_succeeded' || ev.event_type === 'platform_select') {
        profile.platform_counts[plat] = (profile.platform_counts[plat] || 0) + 1;
      }
    }

    // Recompute most_used_platform
    let topPlat = profile.most_used_platform || 'none';
    let topCount = 0;
    for (const [p, c] of Object.entries(profile.platform_counts || {})) {
      if (c > topCount) {
        topCount = c;
        topPlat = p;
      }
    }
    profile.most_used_platform = topPlat;

    visitorsDirty = true;
    saveVisitorsIndex(false);
  }

  function recordActivityEvent(
    req: Request,
    params: {
      res?: Response;
      visitor_id?: string;
      session_id?: string;
      event_category: ActivityEventCategory;
      event_type: ActivityEventType;
      status: ActivityEventStatus;
      platform?: string;
      raw_url_or_text?: string;
      normalized_hostname?: string;
      valid_url?: boolean | null;
      download_initiated?: boolean;
      download_stage?: DownloadLifecycleStage;
      request_id?: string;
      download_method?: string;
      quality?: string;
      format?: string;
      http_status?: number;
      error_category?: string | null;
      duration_ms?: number;
      bytes_transferred?: number;
      detail?: string;
      dedup_window_ms?: number;
    }
  ): ActivityEventRecord | null {
    const ctx = resolveVisitorContext(req, params.res, {
      visitor_id: params.visitor_id,
      session_id: params.session_id
    });

    const reqId = (params.request_id || 'req_' + crypto.randomBytes(6).toString('hex')).slice(0, 48);
    const dedupKey = `${ctx.visitor_id}:${params.event_type}:${params.download_stage || ''}:${params.request_id || params.raw_url_or_text || ''}`;
    if (params.dedup_window_ms !== 0 && shouldDeduplicateEvent(dedupKey, params.dedup_window_ms ?? 2000)) {
      return null;
    }

    let normHost = params.normalized_hostname || '';
    let validUrl: boolean | null = params.valid_url ?? null;
    if (!normHost && params.raw_url_or_text) {
      const extracted = extractNormalizedHostAndPath(params.raw_url_or_text);
      normHost = extracted.normalized_hostname;
      if (validUrl === null) validUrl = extracted.valid_url;
    }
    if (!normHost) {
      normHost = String(req.path || '/').slice(0, 64);
    }

    const record: ActivityEventRecord = {
      event_id: 'act_' + crypto.randomBytes(6).toString('hex'),
      timestamp: new Date().toISOString(),
      visitor_id: ctx.visitor_id,
      session_id: ctx.session_id,
      ip_address: ctx.ip_address,
      ip_version: ctx.ip_version,
      ip_hash: ctx.ip_hash,
      event_category: params.event_category,
      event_type: params.event_type,
      status: params.status,
      platform: (params.platform || 'unknown').toLowerCase().slice(0, 24),
      normalized_hostname: normHost.slice(0, 80),
      valid_url: validUrl,
      download_initiated: Boolean(params.download_initiated),
      ...(params.download_stage ? { download_stage: params.download_stage } : {}),
      request_id: reqId,
      ...(params.download_method ? { download_method: String(params.download_method).slice(0, 40) } : {}),
      ...(params.quality ? { quality: String(params.quality).slice(0, 32) } : {}),
      ...(params.format ? { format: String(params.format).slice(0, 24) } : {}),
      ...(params.http_status !== undefined ? { http_status: Number(params.http_status) } : {}),
      ...(params.error_category !== undefined ? { error_category: params.error_category } : {}),
      ...(params.duration_ms !== undefined ? { duration_ms: Math.max(0, Math.round(params.duration_ms)) } : {}),
      ...(params.bytes_transferred !== undefined ? { bytes_transferred: Math.max(0, Math.round(params.bytes_transferred)) } : {}),
      user_agent_summary: ctx.user_agent_summary,
      device_category: ctx.device_category,
      ...(params.detail ? { detail: sanitizeLogSummary(params.detail) } : {})
    };

    appendJsonlSafe(ACTIVITY_LOG_FILE, record, 12 * 1024 * 1024);
    updateVisitorProfileFromEvent(ctx, record);
    return record;
  }

  // ---------------- 5. Admin Users & Bootstrap Setup ----------------

  let adminUsers: AdminUser[] = readJsonFileSafe<AdminUser[]>(USERS_FILE, []);
  let generatedSetupToken = '';

  function saveAdminUsers(): void {
    writeJsonFileAtomic(USERS_FILE, adminUsers);
  }

  function bootstrapAdminUsersOnStartup(): void {
    const envUsername = (process.env.ADMIN_USERNAME || 'admin').trim().toLowerCase();
    const envEmail = (process.env.ADMIN_EMAIL || process.env.CONTACT_TO_EMAIL || 'admin@downdouyin.com').trim();
    const envInitialPassword = (process.env.ADMIN_INITIAL_PASSWORD || '').trim();
    const envPasswordHash = (process.env.ADMIN_PASSWORD_HASH || '').trim();
    const envResetPassword = (process.env.ADMIN_RESET_PASSWORD || '').trim();

    if (envResetPassword && envResetPassword.length >= 10 && adminUsers.length > 0) {
      const targetUser = adminUsers.find(u => u.username === envUsername) || adminUsers[0];
      targetUser.password_hash = hashPasswordScrypt(envResetPassword);
      targetUser.updated_at = new Date().toISOString();
      targetUser.disabled = false;
      saveAdminUsers();
      recordAuditLog({
        actor: 'system_env',
        action: 'admin_password_reset_via_env',
        target: targetUser.username,
        status: 'warning',
        detail: 'Administrator password was reset via ADMIN_RESET_PASSWORD environment variable on startup.'
      });
    }

    if (adminUsers.length === 0) {
      if (envPasswordHash && envPasswordHash.startsWith('scrypt$')) {
        const now = new Date().toISOString();
        adminUsers.push({
          id: 'usr_' + crypto.randomBytes(6).toString('hex'),
          username: envUsername,
          email: envEmail,
          role: 'owner',
          password_hash: envPasswordHash,
          created_at: now,
          updated_at: now,
          last_login_at: null,
          disabled: false
        });
        saveAdminUsers();
        recordAuditLog({
          actor: 'system_env',
          action: 'initial_admin_provisioned',
          target: envUsername,
          status: 'success',
          detail: 'Initial owner account provisioned from ADMIN_PASSWORD_HASH.'
        });
      } else if (envInitialPassword && envInitialPassword.length >= 10) {
        const now = new Date().toISOString();
        adminUsers.push({
          id: 'usr_' + crypto.randomBytes(6).toString('hex'),
          username: envUsername,
          email: envEmail,
          role: 'owner',
          password_hash: hashPasswordScrypt(envInitialPassword),
          created_at: now,
          updated_at: now,
          last_login_at: null,
          disabled: false
        });
        saveAdminUsers();
        recordAuditLog({
          actor: 'system_env',
          action: 'initial_admin_provisioned',
          target: envUsername,
          status: 'success',
          detail: 'Initial owner account provisioned from ADMIN_INITIAL_PASSWORD.'
        });
      } else {
        const envSetupToken = (process.env.ADMIN_SETUP_TOKEN || '').trim();
        if (envSetupToken && envSetupToken.length >= 12) {
          generatedSetupToken = envSetupToken;
        } else {
          try {
            if (fs.existsSync(SETUP_TOKEN_FILE)) {
              const existing = fs.readFileSync(SETUP_TOKEN_FILE, 'utf8').trim();
              if (existing.length >= 24) {
                generatedSetupToken = existing;
              }
            }
            if (!generatedSetupToken) {
              generatedSetupToken = crypto.randomBytes(24).toString('hex');
              fs.writeFileSync(SETUP_TOKEN_FILE, generatedSetupToken + '\n', { encoding: 'utf8', mode: 0o600 });
            }
          } catch {
            generatedSetupToken = crypto.randomBytes(24).toString('hex');
          }
        }
        console.log(
          `[Admin Control Center] No admin user configured yet. Set ADMIN_INITIAL_PASSWORD in .env or complete one-time setup at /admin using the token in logs/admin-setup-token.txt`
        );
      }
    }
  }
  bootstrapAdminUsersOnStartup();

  // ---------------- 6. Session Management & Rate Limiting ----------------

  const activeSessions = new Map<string, AdminSession>();

  function loadSessionsFromDisk(): void {
    const stored = readJsonFileSafe<AdminSession[]>(SESSIONS_FILE, []);
    const now = Date.now();
    for (const s of stored) {
      if (s && s.sid_hash && s.expires_at > now) {
        activeSessions.set(s.sid_hash, s);
      }
    }
  }
  loadSessionsFromDisk();

  function persistSessionsToDisk(): void {
    const now = Date.now();
    const valid: AdminSession[] = [];
    for (const [k, v] of activeSessions.entries()) {
      if (v.expires_at > now) {
        valid.push(v);
      } else {
        activeSessions.delete(k);
      }
    }
    writeJsonFileAtomic(SESSIONS_FILE, valid);
  }

  function createSessionForUser(user: AdminUser, req: Request, res: Response): { sessionId: string; session: AdminSession } {
    const rawSid = crypto.randomBytes(32).toString('hex');
    const sidHash = sha256Hex(rawSid);
    const csrfToken = crypto.randomBytes(24).toString('hex');
    const now = Date.now();
    const ttlMs = Math.max(1, Math.min(168, adminSettings.session_ttl_hours || 12)) * 3600 * 1000;

    const session: AdminSession = {
      sid_hash: sidHash,
      user_id: user.id,
      username: user.username,
      role: user.role,
      csrf_token: csrfToken,
      created_at: now,
      expires_at: now + ttlMs,
      last_active_at: now,
      user_agent_summary: summarizeUserAgent(req.headers['user-agent'])
    };

    activeSessions.set(sidHash, session);
    persistSessionsToDisk();

    const isSecure =
      req.secure ||
      String(req.headers['x-forwarded-proto'] || '').toLowerCase() === 'https' ||
      process.env.NODE_ENV === 'production';

    const maxAgeSec = Math.floor(ttlMs / 1000);
    const cookieParts = [
      `${ADMIN_COOKIE_NAME}=${encodeURIComponent(rawSid)}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      `Max-Age=${maxAgeSec}`
    ];
    if (isSecure) cookieParts.push('Secure');
    res.setHeader('Set-Cookie', cookieParts.join('; '));

    return { sessionId: rawSid, session };
  }

  function clearSessionCookie(res: Response): void {
    res.setHeader(
      'Set-Cookie',
      `${ADMIN_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
    );
  }

  function getAuthenticatedSession(req: Request): AdminSession | null {
    const cookies = parseCookies(req.headers.cookie);
    const rawSid = cookies[ADMIN_COOKIE_NAME];
    if (!rawSid || rawSid.length < 32) return null;
    const sidHash = sha256Hex(rawSid);
    const session = activeSessions.get(sidHash);
    if (!session) return null;
    const now = Date.now();
    if (session.expires_at <= now) {
      activeSessions.delete(sidHash);
      persistSessionsToDisk();
      return null;
    }
    const user = adminUsers.find(u => u.id === session.user_id && !u.disabled);
    if (!user) {
      activeSessions.delete(sidHash);
      persistSessionsToDisk();
      return null;
    }
    session.last_active_at = now;
    return session;
  }

  const loginAttemptsByKey = new Map<string, { count: number; firstAttemptAt: number; lockedUntil: number }>();
  const LOGIN_WINDOW_MS = 15 * 60 * 1000;
  const MAX_LOGIN_ATTEMPTS = 5;
  const LOCKOUT_MS = 15 * 60 * 1000;

  function checkLoginRateLimit(key: string): { allowed: boolean; retryAfterSec: number } {
    const now = Date.now();
    const rec = loginAttemptsByKey.get(key);
    if (!rec) return { allowed: true, retryAfterSec: 0 };
    if (rec.lockedUntil > now) {
      return { allowed: false, retryAfterSec: Math.ceil((rec.lockedUntil - now) / 1000) };
    }
    if (now - rec.firstAttemptAt > LOGIN_WINDOW_MS) {
      loginAttemptsByKey.delete(key);
      return { allowed: true, retryAfterSec: 0 };
    }
    return { allowed: true, retryAfterSec: 0 };
  }

  function recordFailedLoginAttempt(key: string): void {
    const now = Date.now();
    const rec = loginAttemptsByKey.get(key);
    if (!rec || now - rec.firstAttemptAt > LOGIN_WINDOW_MS) {
      loginAttemptsByKey.set(key, { count: 1, firstAttemptAt: now, lockedUntil: 0 });
      return;
    }
    rec.count++;
    if (rec.count >= MAX_LOGIN_ATTEMPTS) {
      rec.lockedUntil = now + LOCKOUT_MS;
    }
  }

  function clearFailedLoginAttempts(key: string): void {
    loginAttemptsByKey.delete(key);
  }

  function requireAdminAuth(minRole: AdminRole = 'viewer') {
    const roleRank: Record<AdminRole, number> = { viewer: 1, admin: 2, owner: 3 };
    return (req: Request, res: Response, next: NextFunction) => {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('X-Robots-Tag', 'noindex, nofollow');

      const session = getAuthenticatedSession(req);
      if (!session) {
        return res.status(401).json({
          success: false,
          error: 'Unauthorized: Please sign in to access the Admin Control Center.'
        });
      }

      if (roleRank[session.role] < roleRank[minRole]) {
        return res.status(403).json({
          success: false,
          error: 'Forbidden: Insufficient administrator privileges for this action.'
        });
      }

      const method = req.method.toUpperCase();
      if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
        const providedCsrf = String(req.headers['x-csrf-token'] || req.body?._csrf || '').trim();
        if (!providedCsrf || !timingSafeHexEqual(providedCsrf, session.csrf_token)) {
          return res.status(403).json({
            success: false,
            error: 'Forbidden: Invalid or missing CSRF security token.'
          });
        }
      }

      (req as any).adminSession = session;
      next();
    };
  }

  // ---------------- 7. Transactional Email Provider (Resend) & Alerting ----------------

  const alertCooldownMap = new Map<string, number>();
  let recentFailureTimestamps: number[] = [];

  function isResendConfigured(): boolean {
    const key = (process.env.RESEND_API_KEY || '').trim();
    return Boolean(key && key.length >= 10);
  }

  async function sendTransactionalEmail(params: {
    eventType: EmailDeliveryRecord['event_type'];
    to: string;
    subject: string;
    textBody: string;
    htmlBody?: string;
    replyTo?: string;
  }): Promise<{ sent: boolean; providerId?: string; error?: string; status: EmailDeliveryRecord['status'] }> {
    const deliveryId = 'eml_' + crypto.randomBytes(6).toString('hex');
    const toAddr = (params.to || adminSettings.notification_to_email || adminSettings.admin_alert_email || '').trim();
    const fromAddr = (adminSettings.notification_from_email || process.env.CONTACT_FROM_EMAIL || 'DownDouyin Admin <onboarding@resend.dev>').trim();

    if (!isResendConfigured() || !toAddr) {
      const errReason = !isResendConfigured()
        ? 'RESEND_API_KEY is not configured in server environment'
        : 'Recipient email address is not configured';
      const rec: EmailDeliveryRecord = {
        timestamp: new Date().toISOString(),
        delivery_id: deliveryId,
        event_type: params.eventType,
        recipient: toAddr || 'unconfigured',
        subject: params.subject.slice(0, 140),
        status: 'skipped_not_configured',
        attempts: 0,
        error: errReason
      };
      appendJsonlSafe(EMAIL_LOG_FILE, rec, 2 * 1024 * 1024);
      return { sent: false, error: errReason, status: 'skipped_not_configured' };
    }

    const apiKey = (process.env.RESEND_API_KEY || '').trim();
    let lastError = 'Email delivery failed';
    const maxAttempts = 2;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 8000);
        const resp = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            from: fromAddr,
            to: [toAddr],
            subject: params.subject,
            text: params.textBody,
            ...(params.htmlBody ? { html: params.htmlBody } : {}),
            ...(params.replyTo ? { reply_to: params.replyTo } : {})
          }),
          signal: controller.signal
        }).finally(() => clearTimeout(timer));

        const data: any = await resp.json().catch(() => ({}));
        if (resp.ok && data?.id) {
          const rec: EmailDeliveryRecord = {
            timestamp: new Date().toISOString(),
            delivery_id: deliveryId,
            event_type: params.eventType,
            recipient: toAddr,
            subject: params.subject.slice(0, 140),
            status: 'sent',
            provider_id: String(data.id),
            attempts: attempt
          };
          appendJsonlSafe(EMAIL_LOG_FILE, rec, 2 * 1024 * 1024);
          return { sent: true, providerId: String(data.id), status: 'sent' };
        }

        lastError = String(data?.message || data?.error || `HTTP ${resp.status}`);
        if (resp.status < 500 && resp.status !== 429) {
          break;
        }
        if (attempt < maxAttempts) {
          await new Promise(r => setTimeout(r, 1200 * attempt));
        }
      } catch (err: any) {
        lastError = sanitizeLogSummary(err?.message || 'Network error calling Resend API');
        if (attempt < maxAttempts) {
          await new Promise(r => setTimeout(r, 1200 * attempt));
        }
      }
    }

    const rec: EmailDeliveryRecord = {
      timestamp: new Date().toISOString(),
      delivery_id: deliveryId,
      event_type: params.eventType,
      recipient: toAddr,
      subject: params.subject.slice(0, 140),
      status: 'failed',
      attempts: maxAttempts,
      error: sanitizeLogSummary(lastError)
    };
    appendJsonlSafe(EMAIL_LOG_FILE, rec, 2 * 1024 * 1024);
    return { sent: false, error: sanitizeLogSummary(lastError), status: 'failed' };
  }

  // ---------------- 8. Contact State, Funnel Events, Visitor & Error Hooks ----------------

  let contactStates: Record<string, ContactInquiryState> = readJsonFileSafe<Record<string, ContactInquiryState>>(
    CONTACT_STATE_FILE,
    {}
  );

  function saveContactStates(): void {
    writeJsonFileAtomic(CONTACT_STATE_FILE, contactStates);
  }

  function inferIssueType(category: string): ContactInquiryState['issue_type'] {
    const c = (category || '').toLowerCase();
    if (c.includes('feedback') || c.includes('feature') || c.includes('suggestion')) return 'feedback';
    if (c.includes('bug') || c.includes('error') || c.includes('broken') || c.includes('fail')) return 'bug_report';
    return 'inquiry';
  }

  function getOrInitContactState(rec: RawContactRecord): ContactInquiryState {
    const existing = contactStates[rec.inquiry_id];
    if (existing) return existing;
    const initial: ContactInquiryState = {
      inquiry_id: rec.inquiry_id,
      read: false,
      status: 'open',
      issue_type: inferIssueType(rec.category),
      admin_notes: '',
      email_notification_status: isResendConfigured() ? 'pending' : 'not_configured',
      email_notification_at: null,
      email_notification_error: null,
      updated_at: rec.timestamp || new Date().toISOString(),
      timeline: [
        {
          timestamp: rec.timestamp || new Date().toISOString(),
          action: 'submitted',
          actor: 'visitor',
          detail: `Submitted via public contact form (${rec.category || 'general'})`
        }
      ]
    };
    contactStates[rec.inquiry_id] = initial;
    return initial;
  }

  function recordContactFunnelEvent(
    eventType: ContactFunnelEventType,
    meta?: { category?: string; platform?: string; reason?: string; inquiry_id?: string }
  ): void {
    const ev: ContactFunnelEvent = {
      timestamp: new Date().toISOString(),
      event_id: 'cfe_' + crypto.randomBytes(5).toString('hex'),
      event_type: eventType,
      ...(meta?.category ? { category: String(meta.category).slice(0, 48) } : {}),
      ...(meta?.platform ? { platform: String(meta.platform).slice(0, 24) } : {}),
      ...(meta?.reason ? { reason: sanitizeLogSummary(meta.reason).slice(0, 80) } : {}),
      ...(meta?.inquiry_id ? { inquiry_id: String(meta.inquiry_id).slice(0, 32) } : {})
    };
    appendJsonlSafe(CONTACT_FUNNEL_FILE, ev, 3 * 1024 * 1024);
  }

  function recordVisitorEvent(
    req: Request,
    eventType: VisitorTelemetryEvent['event_type'],
    extra?: { platform?: string; res?: Response; visitor_id?: string; session_id?: string }
  ): void {
    let refHost = 'direct';
    const rawRef = String(req.headers.referer || req.headers.referrer || '').trim();
    if (rawRef) {
      try {
        const u = new URL(rawRef);
        const h = u.hostname.toLowerCase();
        if (h && !h.includes('downdouyin.com') && h !== 'localhost' && h !== '127.0.0.1') {
          refHost = h.slice(0, 64);
        }
      } catch {}
    }
    const acceptLang = String(req.headers['accept-language'] || '').toLowerCase();
    const lang = acceptLang.startsWith('zh') ? 'zh' : 'en';

    const ctx = resolveVisitorContext(req, extra?.res, {
      visitor_id: extra?.visitor_id,
      session_id: extra?.session_id
    });

    const ev: VisitorTelemetryEvent = {
      timestamp: new Date().toISOString(),
      event_type: eventType,
      path: String(req.path || '/').slice(0, 64),
      referrer_host: refHost,
      device_category: ctx.device_category,
      lang,
      ...(extra?.platform ? { platform: String(extra.platform).slice(0, 24) } : {}),
      visitor_id: ctx.visitor_id,
      session_id: ctx.session_id,
      ip_address: ctx.ip_address,
      ip_version: ctx.ip_version
    };
    appendJsonlSafe(VISITOR_LOG_FILE, ev, 5 * 1024 * 1024);

    if (eventType === 'page_view') {
      recordActivityEvent(req, {
        res: extra?.res,
        visitor_id: ctx.visitor_id,
        session_id: ctx.session_id,
        event_category: 'navigation',
        event_type: 'page_view',
        status: 'info',
        platform: extra?.platform || 'unknown',
        normalized_hostname: String(req.path || '/').slice(0, 64),
        detail: `Page view (${refHost})`,
        dedup_window_ms: 1500
      });
    }
  }

  function recordAppError(params: {
    requestId?: string;
    severity?: AppErrorRecord['severity'];
    routeCategory: AppErrorRecord['route_category'];
    platform?: string;
    httpStatus: number;
    errorCategory: string;
    durationMs?: number;
    summary: string;
  }): void {
    const now = Date.now();
    const entry: AppErrorRecord = {
      timestamp: new Date(now).toISOString(),
      event_id: 'err_' + crypto.randomBytes(6).toString('hex'),
      request_id: (params.requestId || 'req_' + crypto.randomBytes(4).toString('hex')).slice(0, 48),
      severity: params.severity || (params.httpStatus >= 500 ? 'error' : 'warn'),
      route_category: params.routeCategory,
      platform: (params.platform || 'unknown').slice(0, 24),
      http_status: params.httpStatus,
      error_category: (params.errorCategory || 'unknown_error').slice(0, 48),
      duration_ms: Math.max(0, Math.round(params.durationMs || 0)),
      summary: sanitizeLogSummary(params.summary)
    };
    appendJsonlSafe(ERRORS_LOG_FILE, entry, 5 * 1024 * 1024);

    recentFailureTimestamps = recentFailureTimestamps.filter(ts => now - ts < 10 * 60 * 1000);
    recentFailureTimestamps.push(now);

    const threshold = Math.max(3, adminSettings.repeated_failure_threshold || 5);
    if (
      adminSettings.notify_on_repeated_failures &&
      recentFailureTimestamps.length >= threshold &&
      isResendConfigured()
    ) {
      const lastAlert = alertCooldownMap.get('repeated_failures') || 0;
      if (now - lastAlert > 30 * 60 * 1000) {
        alertCooldownMap.set('repeated_failures', now);
        const alertTo = adminSettings.admin_alert_email || adminSettings.notification_to_email;
        if (alertTo) {
          void sendTransactionalEmail({
            eventType: 'repeated_failure_alert',
            to: alertTo,
            subject: `[DownDouyin Alert] ${recentFailureTimestamps.length} API/Download Failures in 10m`,
            textBody: [
              `DownDouyin detected ${recentFailureTimestamps.length} errors within the last 10 minutes.`,
              `Latest error category: ${entry.error_category} (${entry.route_category}, platform: ${entry.platform})`,
              `Reference ID: ${entry.request_id}`,
              `Timestamp: ${entry.timestamp}`,
              `Summary: ${entry.summary}`
            ].join('\n')
          });
        }
      }
    } else if (
      adminSettings.notify_on_app_errors &&
      entry.severity === 'critical' &&
      isResendConfigured()
    ) {
      const lastCrit = alertCooldownMap.get('critical_error') || 0;
      if (now - lastCrit > 15 * 60 * 1000) {
        alertCooldownMap.set('critical_error', now);
        const alertTo = adminSettings.admin_alert_email || adminSettings.notification_to_email;
        if (alertTo) {
          void sendTransactionalEmail({
            eventType: 'error_alert',
            to: alertTo,
            subject: `[DownDouyin Critical Error] ${entry.route_category} (${entry.error_category})`,
            textBody: [
              `A critical application error occurred on DownDouyin.`,
              `Route: ${entry.route_category}`,
              `Error Category: ${entry.error_category}`,
              `Reference ID: ${entry.request_id}`,
              `Timestamp: ${entry.timestamp}`,
              `Summary: ${entry.summary}`
            ].join('\n')
          });
        }
      }
    }
  }

  async function onNewContactInquiryStored(record: RawContactRecord): Promise<void> {
    recordContactFunnelEvent('submission_stored', {
      category: record.category,
      platform: record.platform,
      inquiry_id: record.inquiry_id
    });

    const state = getOrInitContactState(record);
    const isFeedback = state.issue_type === 'feedback';
    const shouldEmail = isFeedback ? adminSettings.notify_on_feedback : adminSettings.notify_on_contact;

    if (!shouldEmail || !isResendConfigured()) {
      state.email_notification_status = 'not_configured';
      saveContactStates();
      return;
    }

    const toEmail = adminSettings.notification_to_email || adminSettings.admin_alert_email;
    const res = await sendTransactionalEmail({
      eventType: isFeedback ? 'feedback' : 'contact_inquiry',
      to: toEmail,
      replyTo: record.email,
      subject: `[DownDouyin ${isFeedback ? 'Feedback' : 'Inquiry'}] #${record.inquiry_id} (${record.category})`,
      textBody: [
        `New ${isFeedback ? 'feedback' : 'contact inquiry'} received on DownDouyin.com`,
        ``,
        `Reference ID: ${record.inquiry_id}`,
        `Submitted At: ${record.timestamp}`,
        `Name: ${record.name}`,
        `Email: ${record.email}`,
        `Category: ${record.category}`,
        `Platform: ${record.platform}`,
        ``,
        `Message:`,
        record.message
      ].join('\n')
    });

    state.email_notification_at = new Date().toISOString();
    if (res.sent) {
      state.email_notification_status = 'sent';
      state.email_notification_error = null;
      state.timeline.push({
        timestamp: state.email_notification_at,
        action: 'email_notification_sent',
        actor: 'system',
        detail: `Notification delivered via Resend (${res.providerId || 'ok'})`
      });
      recordContactFunnelEvent('email_sent', {
        category: record.category,
        platform: record.platform,
        inquiry_id: record.inquiry_id
      });
    } else {
      state.email_notification_status = res.status === 'skipped_not_configured' ? 'not_configured' : 'failed';
      state.email_notification_error = res.error || 'Delivery failed';
      state.timeline.push({
        timestamp: state.email_notification_at,
        action: 'email_notification_failed',
        actor: 'system',
        detail: res.error || 'Email delivery failed'
      });
      if (res.status === 'failed') {
        recordContactFunnelEvent('email_failed', {
          category: record.category,
          platform: record.platform,
          inquiry_id: record.inquiry_id,
          reason: res.error
        });
      }
    }
    saveContactStates();
  }

  // ---------------- 9. Optional Google Service Account JWT Helper (GA4 & Search Console) ----------------

  let cachedGoogleAccessToken: { token: string; expiresAt: number; scopeKey: string } | null = null;

  function parseGoogleServiceAccount(): { client_email: string; private_key: string } | null {
    const raw = (process.env.GOOGLE_SERVICE_ACCOUNT_JSON || '').trim();
    if (!raw) return null;
    try {
      const decoded = raw.startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8');
      const parsed = JSON.parse(decoded);
      if (parsed && typeof parsed.client_email === 'string' && typeof parsed.private_key === 'string') {
        return {
          client_email: parsed.client_email,
          private_key: parsed.private_key.replace(/\\n/g, '\n')
        };
      }
    } catch {}
    return null;
  }

  async function getGoogleServiceAccountToken(scopes: string[]): Promise<string | null> {
    const sa = parseGoogleServiceAccount();
    if (!sa) return null;
    const scopeKey = scopes.sort().join(' ');
    if (
      cachedGoogleAccessToken &&
      cachedGoogleAccessToken.scopeKey === scopeKey &&
      cachedGoogleAccessToken.expiresAt - 60000 > Date.now()
    ) {
      return cachedGoogleAccessToken.token;
    }

    try {
      const nowSec = Math.floor(Date.now() / 1000);
      const headerB64 = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
      const payloadB64 = Buffer.from(
        JSON.stringify({
          iss: sa.client_email,
          scope: scopeKey,
          aud: 'https://oauth2.googleapis.com/token',
          iat: nowSec,
          exp: nowSec + 3600
        })
      ).toString('base64url');

      const unsigned = `${headerB64}.${payloadB64}`;
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(unsigned);
      const signatureB64 = signer.sign(sa.private_key, 'base64url');
      const assertion = `${unsigned}.${signatureB64}`;

      const resp = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion
        }).toString()
      });
      if (!resp.ok) return null;
      const data: any = await resp.json();
      if (data?.access_token) {
        cachedGoogleAccessToken = {
          token: String(data.access_token),
          expiresAt: Date.now() + (Number(data.expires_in) || 3600) * 1000,
          scopeKey
        };
        return cachedGoogleAccessToken.token;
      }
    } catch {}
    return null;
  }

  // ---------------- 10. Date Range Filtering Helper ----------------

  function resolveDateRangeWindow(query: any): {
    preset: string;
    startMs: number;
    endMs: number;
    prevStartMs: number;
    prevEndMs: number;
    startDateStr: string;
    endDateStr: string;
  } {
    const preset = String(query?.range || '7d').trim().toLowerCase();
    const now = new Date();
    const todayStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())).getTime();
    const dayMs = 24 * 3600 * 1000;

    let startMs = todayStart - 6 * dayMs;
    let endMs = now.getTime();

    if (preset === '24h') {
      startMs = now.getTime() - dayMs;
      endMs = now.getTime();
    } else if (preset === 'today') {
      startMs = todayStart;
      endMs = now.getTime();
    } else if (preset === 'yesterday') {
      startMs = todayStart - dayMs;
      endMs = todayStart - 1;
    } else if (preset === '7d') {
      startMs = todayStart - 6 * dayMs;
    } else if (preset === '28d' || preset === '30d') {
      startMs = todayStart - 29 * dayMs;
    } else if (preset === '90d') {
      startMs = todayStart - 89 * dayMs;
    } else if (preset === 'custom' && query?.start && query?.end) {
      const s = Date.parse(String(query.start));
      const e = Date.parse(String(query.end) + 'T23:59:59.999Z');
      if (!Number.isNaN(s) && !Number.isNaN(e) && s <= e) {
        startMs = s;
        endMs = e;
      }
    }

    const spanMs = Math.max(dayMs, endMs - startMs);
    const prevEndMs = startMs - 1;
    const prevStartMs = prevEndMs - spanMs;

    return {
      preset,
      startMs,
      endMs,
      prevStartMs,
      prevEndMs,
      startDateStr: new Date(startMs).toISOString().slice(0, 10),
      endDateStr: new Date(endMs).toISOString().slice(0, 10)
    };
  }

  // ==================== PUBLIC & SHORTCUT ROUTES ====================

  // 1. Private Admin UI Route (/admin)
  app.get(['/admin', '/admin/'], (req: Request, res: Response) => {
    const adminHtmlPath = path.join(staticDir, 'admin.html');
    if (!fs.existsSync(adminHtmlPath)) {
      return res.status(404).send('Admin interface file not found');
    }
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.send(fs.readFileSync(adminHtmlPath, 'utf8'));
  });

  // 2. Public Upgrade & Pricing Config Endpoint (/api/public/pricing)
  app.get('/api/public/pricing', (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      success: true,
      pricing: adminSettings.pricing_config || DEFAULT_PRICING_CONFIG
    });
  });

  // 3. Public Search-Box Shortcut Check (Never authenticates; only returns { matched: true, redirect: '/admin' })
  const shortcutRateLimitMap = new Map<string, number[]>();
  app.post('/api/public/shortcut-check', (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    if (!adminSettings.shortcut_enabled || !adminSettings.shortcut_phrase_hash) {
      return res.json({ matched: false });
    }
    const ipHash = hashClientIp(req);
    const now = Date.now();
    const recent = (shortcutRateLimitMap.get(ipHash) || []).filter(ts => now - ts < 60000);
    if (recent.length >= 20) {
      return res.json({ matched: false });
    }
    recent.push(now);
    shortcutRateLimitMap.set(ipHash, recent);

    const rawInput = typeof req.body?.input === 'string' ? req.body.input.trim() : '';
    if (!rawInput || rawInput.length > 64) {
      return res.json({ matched: false });
    }
    const candidateHash = sha256Hex(rawInput);
    const isMatch = timingSafeHexEqual(candidateHash, adminSettings.shortcut_phrase_hash);
    if (isMatch) {
      return res.json({ matched: true, redirect: '/admin' });
    }
    return res.json({ matched: false });
  });

  // 4. Public Telemetry Hook for Visitor Activity, Link/Button Clicks, Download Completion & Contact Funnel
  const telemetryRateMap = new Map<string, number[]>();
  app.post('/api/public/telemetry', (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const ipHash = hashClientIp(req);
    const now = Date.now();
    const hits = (telemetryRateMap.get(ipHash) || []).filter(ts => now - ts < 60000);
    if (hits.length >= 90) {
      return res.status(204).end();
    }
    hits.push(now);
    telemetryRateMap.set(ipHash, hits);

    const eventType = String(req.body?.event_type || '').trim();
    const platform = typeof req.body?.platform === 'string' ? req.body.platform.slice(0, 24) : undefined;
    const category = typeof req.body?.category === 'string' ? req.body.category.slice(0, 48) : undefined;
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.slice(0, 80) : undefined;
    const visitorId = typeof req.body?.visitor_id === 'string' ? req.body.visitor_id.slice(0, 40) : undefined;
    const sessionId = typeof req.body?.session_id === 'string' ? req.body.session_id.slice(0, 40) : undefined;
    const requestId = typeof req.body?.request_id === 'string' ? req.body.request_id.slice(0, 48) : undefined;
    const quality = typeof req.body?.quality === 'string' ? req.body.quality.slice(0, 32) : undefined;
    const format = typeof req.body?.format === 'string' ? req.body.format.slice(0, 24) : undefined;
    const durationMs = Number.isFinite(Number(req.body?.duration_ms)) ? Number(req.body.duration_ms) : undefined;
    const bytesTransferred = Number.isFinite(Number(req.body?.bytes_transferred)) ? Number(req.body.bytes_transferred) : undefined;
    const detail = typeof req.body?.detail === 'string' ? req.body.detail.slice(0, 140) : undefined;

    if (eventType === 'page_view' || eventType === 'link_submit' || eventType === 'download_click') {
      recordVisitorEvent(req, eventType, { platform, res, visitor_id: visitorId, session_id: sessionId });
      if (eventType === 'download_click') {
        recordActivityEvent(req, {
          res,
          visitor_id: visitorId,
          session_id: sessionId,
          event_category: 'download_lifecycle',
          event_type: 'download_requested',
          status: 'processing',
          platform,
          download_initiated: true,
          request_id: requestId,
          quality,
          format,
          detail: detail || `User clicked download (${quality || format || 'default'})`
        });
      }
    } else if (eventType === 'contact_form_opened' || eventType === 'contact_modal_open') {
      recordVisitorEvent(req, 'contact_open', { res, visitor_id: visitorId, session_id: sessionId });
      recordContactFunnelEvent('form_opened', { category, platform });
      recordActivityEvent(req, {
        res,
        visitor_id: visitorId,
        session_id: sessionId,
        event_category: 'modal_interaction',
        event_type: 'contact_modal_open',
        status: 'info',
        platform,
        detail: 'Opened Contact Support modal'
      });
    } else if (eventType === 'contact_validation_failed') {
      recordContactFunnelEvent('validation_failed', { category, platform, reason });
    } else if (eventType === 'upgrade_modal_open') {
      recordActivityEvent(req, {
        res,
        visitor_id: visitorId,
        session_id: sessionId,
        event_category: 'modal_interaction',
        event_type: 'upgrade_modal_open',
        status: 'info',
        platform,
        detail: 'Opened Upgrade & Pricing modal'
      });
    } else if (
      eventType === 'platform_select' ||
      eventType === 'url_focus' ||
      eventType === 'url_paste' ||
      eventType === 'quality_select' ||
      eventType === 'format_select' ||
      eventType === 'settings_modal_open' ||
      eventType === 'cookie_saved' ||
      eventType === 'cookie_cleared' ||
      eventType === 'help_guide_open' ||
      eventType === 'faq_modal_open' ||
      eventType === 'blog_modal_open' ||
      eventType === 'retry' ||
      eventType === 'cancelled' ||
      eventType === 'download_client_completed' ||
      eventType === 'download_failed'
    ) {
      const cat: ActivityEventCategory =
        eventType === 'download_client_completed' || eventType === 'download_failed' || eventType === 'cancelled' || eventType === 'retry'
          ? 'download_lifecycle'
          : eventType === 'settings_modal_open' || eventType === 'cookie_saved' || eventType === 'cookie_cleared'
          ? 'settings'
          : eventType.endsWith('_open')
          ? 'modal_interaction'
          : 'ui_interaction';

      const st: ActivityEventStatus =
        eventType === 'download_client_completed'
          ? 'success'
          : eventType === 'download_failed'
          ? 'failed'
          : eventType === 'cancelled'
          ? 'cancelled'
          : 'info';

      recordActivityEvent(req, {
        res,
        visitor_id: visitorId,
        session_id: sessionId,
        event_category: cat,
        event_type: eventType as ActivityEventType,
        status: st,
        platform,
        download_initiated: eventType === 'download_client_completed' || eventType === 'download_failed',
        download_stage: eventType === 'download_client_completed' ? '4_client_completed' : undefined,
        request_id: requestId,
        quality,
        format,
        duration_ms: durationMs,
        bytes_transferred: bytesTransferred,
        detail: detail || `Client event: ${eventType}`
      });
    }
    return res.status(204).end();
  });

  // ==================== ADMIN AUTHENTICATION ROUTES ====================

  // 1. Check Session / Setup Status (Reveals zero private data if unauthenticated)
  app.get('/api/admin/auth/session', (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    const session = getAuthenticatedSession(req);
    if (!session) {
      return res.json({
        authenticated: false,
        needs_initial_setup: adminUsers.length === 0
      });
    }
    const user = adminUsers.find(u => u.id === session.user_id);
    return res.json({
      authenticated: true,
      needs_initial_setup: false,
      user: {
        id: session.user_id,
        username: session.username,
        email: user?.email || '',
        role: session.role,
        last_login_at: user?.last_login_at || null
      },
      csrf_token: session.csrf_token,
      session_expires_at: new Date(session.expires_at).toISOString()
    });
  });

  // 2. Initial One-Time Owner Account Setup (Only active when adminUsers.length === 0)
  app.post('/api/admin/auth/setup', (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    if (adminUsers.length > 0) {
      return res.status(403).json({
        success: false,
        error: 'Initial setup has already been completed. Please sign in with your administrator credentials.'
      });
    }

    const ipHash = hashClientIp(req);
    const limitCheck = checkLoginRateLimit('setup_' + ipHash);
    if (!limitCheck.allowed) {
      return res.status(429).json({
        success: false,
        error: `Too many setup attempts. Please wait ${limitCheck.retryAfterSec} seconds.`
      });
    }

    const setupToken = String(req.body?.setup_token || '').trim();
    const username = String(req.body?.username || 'admin').trim().toLowerCase();
    const email = String(req.body?.email || '').trim();
    const password = String(req.body?.password || '');

    if (!generatedSetupToken || !setupToken || !timingSafeHexEqual(sha256Hex(setupToken), sha256Hex(generatedSetupToken))) {
      recordFailedLoginAttempt('setup_' + ipHash);
      recordAuditLog({
        actor: username || 'unknown',
        action: 'initial_setup_failed',
        target: 'admin_setup',
        req,
        status: 'failed',
        detail: 'Invalid one-time setup token provided.'
      });
      return res.status(401).json({
        success: false,
        error: 'Invalid setup token. Check logs/admin-setup-token.txt or ADMIN_SETUP_TOKEN on the server.'
      });
    }

    if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
      return res.status(400).json({
        success: false,
        error: 'Username must be 3–32 characters (letters, numbers, _, ., -).'
      });
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Please enter a valid administrator email address.'
      });
    }
    if (!password || password.length < 10) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 10 characters long.'
      });
    }

    const now = new Date().toISOString();
    const newUser: AdminUser = {
      id: 'usr_' + crypto.randomBytes(6).toString('hex'),
      username,
      email,
      role: 'owner',
      password_hash: hashPasswordScrypt(password),
      created_at: now,
      updated_at: now,
      last_login_at: now,
      disabled: false
    };

    adminUsers.push(newUser);
    saveAdminUsers();
    generatedSetupToken = '';
    try {
      if (fs.existsSync(SETUP_TOKEN_FILE)) fs.unlinkSync(SETUP_TOKEN_FILE);
    } catch {}

    if (!adminSettings.notification_to_email) {
      adminSettings.notification_to_email = email;
      adminSettings.admin_alert_email = email;
      saveAdminSettings();
    }

    clearFailedLoginAttempts('setup_' + ipHash);
    const { session } = createSessionForUser(newUser, req, res);

    recordAuditLog({
      actor: newUser.username,
      action: 'initial_setup_completed',
      target: newUser.username,
      req,
      status: 'success',
      detail: 'Initial owner administrator account created via setup token.'
    });

    return res.json({
      success: true,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      },
      csrf_token: session.csrf_token
    });
  });

  // 3. Admin Login
  app.post('/api/admin/auth/login', (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const ipHash = hashClientIp(req);
    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    const ipLimit = checkLoginRateLimit('ip_' + ipHash);
    if (!ipLimit.allowed) {
      return res.status(429).json({
        success: false,
        error: `Too many failed sign-in attempts. Please try again in ${ipLimit.retryAfterSec} seconds.`
      });
    }

    const userLimit = username ? checkLoginRateLimit('usr_' + username) : { allowed: true, retryAfterSec: 0 };
    if (!userLimit.allowed) {
      return res.status(429).json({
        success: false,
        error: `Too many failed sign-in attempts. Please try again in ${userLimit.retryAfterSec} seconds.`
      });
    }

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Please enter both username and password.'
      });
    }

    const user = adminUsers.find(u => u.username === username && !u.disabled);
    const dummyHash =
      'scrypt$16384$8$1$00112233445566778899aabbccddeeff$' + '0'.repeat(128);
    const validPassword = verifyPasswordScrypt(password, user ? user.password_hash : dummyHash);

    if (!user || !validPassword) {
      recordFailedLoginAttempt('ip_' + ipHash);
      if (username) recordFailedLoginAttempt('usr_' + username);
      recordAuditLog({
        actor: username || 'unknown',
        action: 'admin_login_failed',
        target: '/admin',
        req,
        status: 'failed',
        detail: 'Invalid username or password attempt.'
      });
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password.'
      });
    }

    const oldCookies = parseCookies(req.headers.cookie);
    if (oldCookies[ADMIN_COOKIE_NAME]) {
      activeSessions.delete(sha256Hex(oldCookies[ADMIN_COOKIE_NAME]));
    }

    clearFailedLoginAttempts('ip_' + ipHash);
    clearFailedLoginAttempts('usr_' + username);

    user.last_login_at = new Date().toISOString();
    saveAdminUsers();

    const { session } = createSessionForUser(user, req, res);

    recordAuditLog({
      actor: user.username,
      action: 'admin_login_success',
      target: '/admin',
      req,
      status: 'success',
      detail: `Signed in (${session.user_agent_summary}).`
    });

    return res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        last_login_at: user.last_login_at
      },
      csrf_token: session.csrf_token
    });
  });

  // 4. Logout Current Session
  app.post('/api/admin/auth/logout', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    activeSessions.delete(session.sid_hash);
    persistSessionsToDisk();
    clearSessionCookie(res);

    recordAuditLog({
      actor: session.username,
      action: 'admin_logout',
      target: '/admin',
      req,
      status: 'success',
      detail: 'Signed out of current session.'
    });

    return res.json({ success: true });
  });

  // 5. Logout All Sessions (Requires current password re-authentication)
  app.post('/api/admin/auth/logout-all', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const currentPassword = String(req.body?.current_password || '');
    const user = adminUsers.find(u => u.id === session.user_id);
    if (!user || !verifyPasswordScrypt(currentPassword, user.password_hash)) {
      return res.status(401).json({
        success: false,
        error: 'Re-authentication failed: Please enter your current password to revoke all sessions.'
      });
    }

    const revokedCount = activeSessions.size;
    activeSessions.clear();
    persistSessionsToDisk();
    clearSessionCookie(res);

    recordAuditLog({
      actor: session.username,
      action: 'admin_logout_all_sessions',
      target: 'all_sessions',
      req,
      status: 'warning',
      detail: `Revoked ${revokedCount} active administrator session(s).`
    });

    return res.json({ success: true, revoked_sessions: revokedCount });
  });

  function getSessionRef(sidHash: string): string {
    return 'ses_' + sha256Hex('dd_sref_v1:' + sidHash).slice(0, 12);
  }

  // 5b. Revoke Individual Session by Safe Reference ID
  app.delete('/api/admin/sessions/:ref', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const currentSession: AdminSession = (req as any).adminSession;
    const targetRef = String(req.params.ref || '').trim();
    if (!targetRef || !/^ses_[a-f0-9]{12}$/.test(targetRef)) {
      return res.status(400).json({ success: false, error: 'Invalid session reference identifier.' });
    }

    let matchedKey: string | null = null;
    let matchedSession: AdminSession | null = null;
    for (const [k, s] of activeSessions.entries()) {
      if (getSessionRef(k) === targetRef) {
        matchedKey = k;
        matchedSession = s;
        break;
      }
    }

    if (!matchedKey || !matchedSession) {
      return res.status(404).json({ success: false, error: 'Active session not found or already expired.' });
    }

    // Non-owner admins cannot revoke an owner's session
    if (matchedSession.role === 'owner' && currentSession.role !== 'owner') {
      return res.status(403).json({ success: false, error: 'Only an Owner can revoke an Owner session.' });
    }

    const revokedSelf = matchedKey === currentSession.sid_hash;
    activeSessions.delete(matchedKey);
    persistSessionsToDisk();
    if (revokedSelf) {
      clearSessionCookie(res);
    }

    recordAuditLog({
      actor: currentSession.username,
      action: 'admin_session_revoked',
      target: `${matchedSession.username} (${targetRef})`,
      req,
      status: 'warning',
      detail: `Revoked individual session ${targetRef} for ${matchedSession.username} (${matchedSession.user_agent_summary}).`
    });

    return res.json({
      success: true,
      revoked_ref: targetRef,
      revoked_current: revokedSelf
    });
  });

  // 6. Change Password / Manage Staff Users
  app.post('/api/admin/auth/change-password', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const currentPassword = String(req.body?.current_password || '');
    const newPassword = String(req.body?.new_password || '');

    if (!newPassword || newPassword.length < 10) {
      return res.status(400).json({
        success: false,
        error: 'New password must be at least 10 characters long.'
      });
    }

    const user = adminUsers.find(u => u.id === session.user_id);
    if (!user || !verifyPasswordScrypt(currentPassword, user.password_hash)) {
      recordAuditLog({
        actor: session.username,
        action: 'password_change_failed',
        target: session.username,
        req,
        status: 'failed',
        detail: 'Current password verification failed during password change.'
      });
      return res.status(401).json({
        success: false,
        error: 'Current password is incorrect.'
      });
    }

    user.password_hash = hashPasswordScrypt(newPassword);
    user.updated_at = new Date().toISOString();
    saveAdminUsers();

    for (const key of activeSessions.keys()) {
      if (key !== session.sid_hash) activeSessions.delete(key);
    }
    persistSessionsToDisk();

    recordAuditLog({
      actor: session.username,
      action: 'password_changed',
      target: session.username,
      req,
      status: 'success',
      detail: 'Administrator password updated and other sessions revoked.'
    });

    return res.json({ success: true });
  });

  // 6b. Create or Update Additional Authorized Staff Accounts (Owner only)
  app.post('/api/admin/users', requireAdminAuth('owner'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const username = String(req.body?.username || '').trim().toLowerCase();
    const email = String(req.body?.email || '').trim();
    const password = String(req.body?.password || '');
    const roleRaw = String(req.body?.role || 'viewer').trim().toLowerCase();
    const role: AdminRole = roleRaw === 'owner' ? 'owner' : roleRaw === 'admin' ? 'admin' : 'viewer';

    if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
      return res.status(400).json({
        success: false,
        error: 'Username must be 3–32 characters (letters, numbers, _, ., -).'
      });
    }
    if (adminUsers.some(u => u.username === username)) {
      return res.status(400).json({
        success: false,
        error: 'An administrator account with that username already exists.'
      });
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Please enter a valid email address.'
      });
    }
    if (!password || password.length < 10) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 10 characters long.'
      });
    }

    const now = new Date().toISOString();
    const staffUser: AdminUser = {
      id: 'usr_' + crypto.randomBytes(6).toString('hex'),
      username,
      email,
      role,
      password_hash: hashPasswordScrypt(password),
      created_at: now,
      updated_at: now,
      last_login_at: null,
      disabled: false
    };
    adminUsers.push(staffUser);
    saveAdminUsers();

    recordAuditLog({
      actor: session.username,
      action: 'staff_user_created',
      target: `${username} (${role})`,
      req,
      status: 'success',
      detail: `Created authorized staff account ${username} with role ${role}.`
    });

    return res.json({
      success: true,
      user: {
        id: staffUser.id,
        username: staffUser.username,
        email: staffUser.email,
        role: staffUser.role,
        created_at: staffUser.created_at,
        disabled: staffUser.disabled
      }
    });
  });

  app.patch('/api/admin/users/:id', requireAdminAuth('owner'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const targetId = String(req.params.id || '').trim();
    const targetUser = adminUsers.find(u => u.id === targetId);
    if (!targetUser) {
      return res.status(404).json({ success: false, error: 'User account not found.' });
    }
    if (targetUser.id === session.user_id && req.body?.disabled === true) {
      return res.status(400).json({ success: false, error: 'You cannot disable your own active account.' });
    }

    const activeOwnersCount = adminUsers.filter(u => u.role === 'owner' && !u.disabled).length;
    const wantsDisable = req.body?.disabled === true && !targetUser.disabled;
    const wantsDemoteOwner =
      targetUser.role === 'owner' &&
      typeof req.body?.role === 'string' &&
      req.body.role !== 'owner';

    if (targetUser.role === 'owner' && (wantsDisable || wantsDemoteOwner) && activeOwnersCount <= 1) {
      return res.status(400).json({
        success: false,
        error: 'Cannot disable or demote the final active Owner account.'
      });
    }

    if (typeof req.body?.disabled === 'boolean') {
      targetUser.disabled = req.body.disabled;
    }
    if (req.body?.role === 'owner' || req.body?.role === 'admin' || req.body?.role === 'viewer') {
      targetUser.role = req.body.role;
    }
    if (typeof req.body?.email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(req.body.email.trim())) {
      targetUser.email = req.body.email.trim();
    }
    targetUser.updated_at = new Date().toISOString();
    saveAdminUsers();

    if (targetUser.disabled) {
      for (const [k, s] of activeSessions.entries()) {
        if (s.user_id === targetUser.id) activeSessions.delete(k);
      }
      persistSessionsToDisk();
    }

    recordAuditLog({
      actor: session.username,
      action: 'staff_user_updated',
      target: targetUser.username,
      req,
      status: 'success',
      detail: `Updated staff account ${targetUser.username} (role=${targetUser.role}, disabled=${targetUser.disabled}).`
    });

    return res.json({ success: true });
  });

  app.delete('/api/admin/users/:id', requireAdminAuth('owner'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const targetId = String(req.params.id || '').trim();
    const idx = adminUsers.findIndex(u => u.id === targetId);
    if (idx < 0) {
      return res.status(404).json({ success: false, error: 'User account not found.' });
    }
    const targetUser = adminUsers[idx];
    if (targetUser.id === session.user_id) {
      return res.status(400).json({ success: false, error: 'You cannot delete your own currently signed-in account.' });
    }
    const activeOwnersCount = adminUsers.filter(u => u.role === 'owner' && !u.disabled).length;
    if (targetUser.role === 'owner' && !targetUser.disabled && activeOwnersCount <= 1) {
      return res.status(400).json({ success: false, error: 'Cannot delete the final active Owner account.' });
    }

    adminUsers.splice(idx, 1);
    saveAdminUsers();

    for (const [k, s] of activeSessions.entries()) {
      if (s.user_id === targetUser.id) activeSessions.delete(k);
    }
    persistSessionsToDisk();

    recordAuditLog({
      actor: session.username,
      action: 'staff_user_deleted',
      target: targetUser.username,
      req,
      status: 'warning',
      detail: `Deleted staff account ${targetUser.username} (${targetUser.role}).`
    });

    return res.json({ success: true, deleted_id: targetId });
  });

  // ==================== ADMIN DASHBOARD DATA ENDPOINTS ====================

  function getBackupsList(): BackupRecord[] {
    const list: BackupRecord[] = [];
    try {
      if (!fs.existsSync(backupsDir)) return list;
      for (const name of fs.readdirSync(backupsDir)) {
        if (!name.endsWith('.json')) continue;
        const full = path.join(backupsDir, name);
        const st = fs.statSync(full);
        if (st.isFile()) {
          list.push({
            backup_id: name.replace(/\.json$/, ''),
            filename: name,
            created_at: st.mtime.toISOString(),
            size_bytes: st.size,
            created_by: 'admin'
          });
        }
      }
      list.sort((a, b) => b.created_at.localeCompare(a.created_at));
    } catch {}
    return list;
  }

  // 1. Overview & Filtered KPIs (/api/admin/overview)
  app.get('/api/admin/overview', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const win = resolveDateRangeWindow(req.query);

    const allDownloadEvents = readJsonlTail<DownloadStatRecord>(STATS_LOG_FILE, 10000);
    const allVisitorEvents = readJsonlTail<VisitorTelemetryEvent>(VISITOR_LOG_FILE, 10000);
    const allActivityEvents = readJsonlTail<ActivityEventRecord>(ACTIVITY_LOG_FILE, 10000);
    const allContacts = readJsonlTail<RawContactRecord>(CONTACT_LOG_FILE, 5000);
    const allErrors = readJsonlTail<AppErrorRecord>(ERRORS_LOG_FILE, 5000);
    const allFunnel = readJsonlTail<ContactFunnelEvent>(CONTACT_FUNNEL_FILE, 5000);

    const inRange = (iso: string, s: number, e: number) => {
      const t = Date.parse(iso);
      return !Number.isNaN(t) && t >= s && t <= e;
    };

    const curDownloads = allDownloadEvents.filter(d => inRange(d.timestamp, win.startMs, win.endMs));
    const prevDownloads = allDownloadEvents.filter(d => inRange(d.timestamp, win.prevStartMs, win.prevEndMs));

    const curVisitors = allVisitorEvents.filter(v => inRange(v.timestamp, win.startMs, win.endMs));
    const prevVisitors = allVisitorEvents.filter(v => inRange(v.timestamp, win.prevStartMs, win.prevEndMs));

    const curActivities = allActivityEvents.filter(a => inRange(a.timestamp, win.startMs, win.endMs));
    const prevActivities = allActivityEvents.filter(a => inRange(a.timestamp, win.prevStartMs, win.prevEndMs));
    const curErrors = allErrors.filter(e => inRange(e.timestamp, win.startMs, win.endMs));
    const prevErrors = allErrors.filter(e => inRange(e.timestamp, win.prevStartMs, win.prevEndMs));

    const summarizeDl = (records: DownloadStatRecord[]) => {
      let parseTotal = 0, parseSuccess = 0, parseFailed = 0;
      let dlTotal = 0, dlSuccess = 0, dlFailed = 0, dlAborted = 0;
      let totalLatencyMs = 0;
      const byPlatform: Record<string, { total: number; success: number; failed: number; parse_total: number; download_total: number }> = {
        douyin: { total: 0, success: 0, failed: 0, parse_total: 0, download_total: 0 },
        bilibili: { total: 0, success: 0, failed: 0, parse_total: 0, download_total: 0 },
        tiktok: { total: 0, success: 0, failed: 0, parse_total: 0, download_total: 0 },
        xiaohongshu: { total: 0, success: 0, failed: 0, parse_total: 0, download_total: 0 }
      };

      for (const r of records) {
        totalLatencyMs += r.duration_ms || 0;
        const p = byPlatform[r.platform];
        if (r.operation === 'parse_request') {
          parseTotal++;
          if (r.status === 'success') parseSuccess++;
          else parseFailed++;
          if (p) {
            p.total++;
            p.parse_total++;
            if (r.status === 'success') p.success++;
            else p.failed++;
          }
        } else {
          dlTotal++;
          if (r.status === 'success') dlSuccess++;
          else if (r.status === 'aborted') dlAborted++;
          else dlFailed++;
          if (p) {
            p.total++;
            p.download_total++;
            if (r.status === 'success') p.success++;
            else if (r.status === 'failed') p.failed++;
          }
        }
      }

      const totalAttempts = parseTotal + dlTotal;
      const totalSuccess = parseSuccess + dlSuccess;
      const totalFailed = parseFailed + dlFailed;
      const nonAborted = totalSuccess + totalFailed;
      const successRate = nonAborted > 0 ? Number(((totalSuccess / nonAborted) * 100).toFixed(1)) : null;
      const failureRate = nonAborted > 0 ? Number(((totalFailed / nonAborted) * 100).toFixed(1)) : null;
      const dlNonAborted = dlSuccess + dlFailed;
      const dlSuccessRate = dlNonAborted > 0 ? Number(((dlSuccess / dlNonAborted) * 100).toFixed(1)) : null;

      return {
        total_attempts: totalAttempts,
        total_success: totalSuccess,
        total_failed: totalFailed,
        parse_total: parseTotal,
        parse_success: parseSuccess,
        parse_failed: parseFailed,
        file_download_total: dlTotal,
        file_download_success: dlSuccess,
        file_download_failed: dlFailed,
        file_download_aborted: dlAborted,
        success_rate_pct: successRate,
        failure_rate_pct: failureRate,
        download_only_success_rate_pct: dlSuccessRate,
        avg_duration_ms: records.length > 0 ? Math.round(totalLatencyMs / records.length) : 0,
        by_platform: byPlatform
      };
    };

    const currentDlSummary = summarizeDl(curDownloads);
    const previousDlSummary = summarizeDl(prevDownloads);
    const allTimeDlSummary = summarizeDl(allDownloadEvents);

    // Visitor & session counts (exact window counts without artificial Math.max inflation)
    const nowMs = Date.now();
    const dayMs = 24 * 3600 * 1000;
    const allVisitorProfiles = Array.from(visitorsMap.values());
    const active24hCount = allVisitorProfiles.filter(v => Date.parse(v.last_active_at) >= nowMs - dayMs).length;
    const active7dCount = allVisitorProfiles.filter(v => Date.parse(v.last_active_at) >= nowMs - 7 * dayMs).length;

    const windowVisitorIds = new Set<string>();
    const windowSessionIds = new Set<string>();
    for (const a of curActivities) {
      if (a.visitor_id) windowVisitorIds.add(a.visitor_id);
      if (a.session_id) windowSessionIds.add(a.session_id);
    }
    for (const v of curVisitors) {
      if (v.visitor_id) windowVisitorIds.add(v.visitor_id);
      if (v.session_id) windowSessionIds.add(v.session_id);
    }
    for (const vp of allVisitorProfiles) {
      if (inRange(vp.last_active_at, win.startMs, win.endMs) || inRange(vp.first_seen_at, win.startMs, win.endMs)) {
        windowVisitorIds.add(vp.visitor_id);
      }
    }

    const prevWindowVisitorIds = new Set<string>();
    for (const a of prevActivities) {
      if (a.visitor_id) prevWindowVisitorIds.add(a.visitor_id);
    }
    for (const v of prevVisitors) {
      if (v.visitor_id) prevWindowVisitorIds.add(v.visitor_id);
    }

    const totalSessionsAllTime = allVisitorProfiles.reduce((acc, v) => acc + (v.session_count || 1), 0);
    const clientConfirmedInWindow = curActivities.filter(a => a.event_type === 'download_client_completed').length;

    // Most popular platforms ranking & most failing platform/endpoint
    const platformRanking = Object.entries(currentDlSummary.by_platform)
      .map(([platform, stats]) => ({
        platform,
        total: stats.total,
        success: stats.success,
        failed: stats.failed,
        parse_total: stats.parse_total,
        download_total: stats.download_total,
        share_pct: currentDlSummary.total_attempts > 0
          ? Number(((stats.total / currentDlSummary.total_attempts) * 100).toFixed(1))
          : 0
      }))
      .sort((a, b) => b.total - a.total);

    const failingPlatforms = [...platformRanking].filter(p => p.failed > 0).sort((a, b) => b.failed - a.failed);
    const mostFailingPlatform = failingPlatforms.length > 0 ? failingPlatforms[0] : null;

    const endpointFailuresMap: Record<string, number> = {};
    for (const e of curErrors) {
      endpointFailuresMap[e.route_category] = (endpointFailuresMap[e.route_category] || 0) + 1;
    }
    for (const d of curDownloads) {
      if (d.status === 'failed') {
        const ep = d.operation === 'parse_request' ? 'parse (/api/parse)' : d.operation === 'zip_download' ? 'zip (/api/zip)' : 'download (/api/download)';
        endpointFailuresMap[ep] = (endpointFailuresMap[ep] || 0) + 1;
      }
    }
    const failingEndpoints = Object.entries(endpointFailuresMap)
      .map(([endpoint, count]) => ({ endpoint, count }))
      .sort((a, b) => b.count - a.count);
    const mostFailingEndpoint = failingEndpoints.length > 0 ? failingEndpoints[0] : null;

    // Top error categories in window
    const topErrorsMap: Record<string, number> = {};
    for (const r of curDownloads) {
      if (r.status === 'failed' && r.error_category) {
        topErrorsMap[r.error_category] = (topErrorsMap[r.error_category] || 0) + 1;
      }
    }
    for (const e of curErrors) {
      if (e.error_category) {
        topErrorsMap[e.error_category] = Math.max(topErrorsMap[e.error_category] || 0, 1);
      }
    }
    const topErrorsList = Object.entries(topErrorsMap)
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);

    // Contact inbox counts
    let unreadInquiries = 0;
    let unresolvedInquiries = 0;
    let feedbackCount = 0;
    let periodInquiries = 0;

    for (const c of allContacts) {
      const st = getOrInitContactState(c);
      if (st.status !== 'spam') {
        if (!st.read) unreadInquiries++;
        if (st.status === 'open' || st.status === 'in_progress') unresolvedInquiries++;
        if (st.issue_type === 'feedback' || st.issue_type === 'bug_report') feedbackCount++;
      }
      if (inRange(c.timestamp, win.startMs, win.endMs)) {
        periodInquiries++;
      }
    }
    saveContactStates();

    // Daily trend series within window
    const dailyMap = new Map<string, { date: string; page_views: number; parse_requests: number; downloads_success: number; downloads_failed: number }>();
    const daySpan = Math.min(90, Math.max(1, Math.ceil((win.endMs - win.startMs) / dayMs)));
    for (let i = daySpan - 1; i >= 0; i--) {
      const dStr = new Date(win.endMs - i * dayMs).toISOString().slice(0, 10);
      dailyMap.set(dStr, { date: dStr, page_views: 0, parse_requests: 0, downloads_success: 0, downloads_failed: 0 });
    }
    for (const v of curVisitors) {
      if (v.event_type === 'page_view') {
        const dStr = v.timestamp.slice(0, 10);
        const bucket = dailyMap.get(dStr);
        if (bucket) bucket.page_views++;
      }
    }
    for (const d of curDownloads) {
      const dStr = d.timestamp.slice(0, 10);
      const bucket = dailyMap.get(dStr);
      if (!bucket) continue;
      if (d.operation === 'parse_request') bucket.parse_requests++;
      if (d.status === 'success') bucket.downloads_success++;
      else if (d.status === 'failed') bucket.downloads_failed++;
    }

    const backups = getBackupsList();
    const ga4DataApiConfigured = Boolean(adminSettings.ga4_property_id && parseGoogleServiceAccount());

    return res.json({
      success: true,
      checked_at: new Date().toISOString(),
      timezone: 'UTC',
      window: {
        preset: win.preset,
        start_date: win.startDateStr,
        end_date: win.endDateStr
      },
      summary_kpis: {
        total_registered_users: adminUsers.length,
        unique_visitors_window: windowVisitorIds.size,
        prev_unique_visitors_window: prevWindowVisitorIds.size,
        unique_visitors_all_time: allVisitorProfiles.length,
        total_sessions_window: Math.max(windowSessionIds.size, windowVisitorIds.size),
        total_sessions_all_time: Math.max(totalSessionsAllTime, allVisitorProfiles.length),
        active_users_24h: active24hCount,
        active_users_7d: active7dCount,
        total_link_submissions: currentDlSummary.parse_total,
        prev_link_submissions: previousDlSummary.parse_total,
        total_download_attempts: currentDlSummary.file_download_total,
        prev_download_attempts: previousDlSummary.file_download_total,
        successful_downloads: currentDlSummary.file_download_success,
        prev_successful_downloads: previousDlSummary.file_download_success,
        client_confirmed_downloads: clientConfirmedInWindow,
        failed_downloads: currentDlSummary.file_download_failed,
        prev_failed_downloads: previousDlSummary.file_download_failed,
        cancelled_downloads: currentDlSummary.file_download_aborted,
        download_success_rate_pct: currentDlSummary.download_only_success_rate_pct ?? currentDlSummary.success_rate_pct,
        download_failure_rate_pct: currentDlSummary.failure_rate_pct,
        total_videos_downloaded_all_time: allTimeDlSummary.file_download_success,
        avg_api_latency_ms: currentDlSummary.avg_duration_ms
      },
      most_popular_platforms: platformRanking,
      most_failing_platform: mostFailingPlatform,
      most_failing_endpoint: mostFailingEndpoint,
      top_error_types: topErrorsList,
      recent_activity: curActivities.slice(-20).reverse(),
      recent_errors: curErrors.slice(-10).reverse(),
      prev_errors_count: prevErrors.length,
      traffic: {
        first_party_page_views: curVisitors.filter(v => v.event_type === 'page_view').length,
        prev_first_party_page_views: prevVisitors.filter(v => v.event_type === 'page_view').length,
        ga4_measurement_id: adminSettings.ga4_measurement_id,
        ga4_data_api_configured: ga4DataApiConfigured,
        unique_visitors_status: 'first_party_tracked'
      },
      downloads: {
        current: currentDlSummary,
        previous: previousDlSummary
      },
      contacts: {
        total_received: allContacts.length,
        period_received: periodInquiries,
        unread_count: unreadInquiries,
        unresolved_count: unresolvedInquiries,
        feedback_count: feedbackCount,
        funnel_period: {
          form_opened: allFunnel.filter(f => inRange(f.timestamp, win.startMs, win.endMs) && f.event_type === 'form_opened').length,
          validation_failed: allFunnel.filter(f => inRange(f.timestamp, win.startMs, win.endMs) && f.event_type === 'validation_failed').length,
          submission_attempted: allFunnel.filter(f => inRange(f.timestamp, win.startMs, win.endMs) && f.event_type === 'submission_attempted').length,
          submission_stored: allFunnel.filter(f => inRange(f.timestamp, win.startMs, win.endMs) && f.event_type === 'submission_stored').length
        }
      },
      health: {
        status: 'healthy',
        uptime_seconds: Math.floor((Date.now() - serverStartTime) / 1000),
        recent_errors_count: curErrors.length,
        last_backup: backups[0] || null,
        email_configured: isResendConfigured()
      },
      daily_series: Array.from(dailyMap.values())
    });
  });

  // 1b. Visitors & User Management (/api/admin/visitors)
  app.get('/api/admin/visitors', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const search = String(req.query.q || '').trim().toLowerCase();
    const statusFilter = String(req.query.status || 'all').trim().toLowerCase();
    const platformFilter = String(req.query.platform || 'all').trim().toLowerCase();
    const ipVersionFilter = String(req.query.ip_version || 'all').trim();
    const sortBy = String(req.query.sort_by || 'last_active_at').trim();
    const sortDir = String(req.query.sort_dir || 'desc').trim().toLowerCase() === 'asc' ? 1 : -1;
    const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
    const pageSize = Math.min(100, Math.max(10, parseInt(String(req.query.page_size || '25'), 10) || 25));

    const nowMs = Date.now();
    const dayMs = 24 * 3600 * 1000;

    const allProfiles = Array.from(visitorsMap.values());
    const filtered = allProfiles.filter(v => {
      if (statusFilter === 'active_24h' && Date.parse(v.last_active_at) < nowMs - dayMs) return false;
      if (statusFilter === 'active_7d' && Date.parse(v.last_active_at) < nowMs - 7 * dayMs) return false;
      if (statusFilter === 'blocked' && !v.blocked) return false;
      if (platformFilter !== 'all' && v.most_used_platform !== platformFilter && !(v.platform_counts?.[platformFilter] > 0)) return false;
      if (ipVersionFilter !== 'all' && v.ip_version !== ipVersionFilter) return false;
      if (search) {
        const hay = `${v.visitor_id} ${v.last_ip} ${v.ip_hash} ${v.most_used_platform} ${v.user_agent_summary} ${v.admin_notes || ''}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    filtered.sort((a: any, b: any) => {
      if (sortBy === 'first_seen_at' || sortBy === 'last_active_at') {
        return String(a[sortBy] || '').localeCompare(String(b[sortBy] || '')) * sortDir;
      }
      const numA = Number(a[sortBy] || 0);
      const numB = Number(b[sortBy] || 0);
      return (numA - numB) * sortDir;
    });

    const total = filtered.length;
    const items = filtered.slice((page - 1) * pageSize, page * pageSize);

    return res.json({
      success: true,
      total,
      page,
      page_size: pageSize,
      summary: {
        total_tracked_visitors: allProfiles.length,
        active_24h: allProfiles.filter(v => Date.parse(v.last_active_at) >= nowMs - dayMs).length,
        active_7d: allProfiles.filter(v => Date.parse(v.last_active_at) >= nowMs - 7 * dayMs).length,
        blocked_count: allProfiles.filter(v => v.blocked).length,
        ipv4_visitors: allProfiles.filter(v => v.ip_version === 'IPv4').length,
        ipv6_visitors: allProfiles.filter(v => v.ip_version === 'IPv6').length
      },
      items
    });
  });

  // 1c. Visitor Detail Modal Endpoint (/api/admin/visitors/:id)
  app.get('/api/admin/visitors/:id', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const vid = String(req.params.id || '').trim();
    const profile = visitorsMap.get(vid);
    if (!profile) {
      return res.status(404).json({ success: false, error: 'Visitor profile not found.' });
    }
    const allActivities = readJsonlTail<ActivityEventRecord>(ACTIVITY_LOG_FILE, 5000);
    const visitorEvents = allActivities.filter(a => a.visitor_id === vid).reverse();

    return res.json({
      success: true,
      profile,
      recent_link_submissions: visitorEvents
        .filter(e => e.event_category === 'link_submission')
        .slice(0, 50),
      recent_downloads: visitorEvents
        .filter(e => e.event_category === 'download_lifecycle')
        .slice(0, 50),
      recent_activity_timeline: visitorEvents.slice(0, 100)
    });
  });

  // 1d. Update Visitor Block / Rate-Limit / Notes (/api/admin/visitors/:id)
  app.patch('/api/admin/visitors/:id', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const vid = String(req.params.id || '').trim();
    const profile = visitorsMap.get(vid);
    if (!profile) {
      return res.status(404).json({ success: false, error: 'Visitor profile not found.' });
    }

    const changes: string[] = [];
    if (typeof req.body?.blocked === 'boolean' && req.body.blocked !== profile.blocked) {
      profile.blocked = req.body.blocked;
      changes.push(profile.blocked ? 'Blocked visitor/IP' : 'Unblocked visitor/IP');
    }
    if (req.body?.rate_limit_override_rpm !== undefined) {
      const val = req.body.rate_limit_override_rpm === null ? null : Math.max(1, Math.min(600, Number(req.body.rate_limit_override_rpm) || 30));
      profile.rate_limit_override_rpm = val;
      changes.push(`Set rate limit override to ${val ?? 'default'}`);
    }
    if (typeof req.body?.admin_notes === 'string') {
      profile.admin_notes = req.body.admin_notes.trim().slice(0, 1000);
      changes.push('Updated visitor notes');
    }

    visitorsDirty = true;
    saveVisitorsIndex(true);

    if (changes.length > 0) {
      recordAuditLog({
        actor: session.username,
        action: 'visitor_profile_updated',
        target: vid,
        req,
        status: profile.blocked ? 'warning' : 'success',
        detail: changes.join('; ')
      });
    }

    return res.json({ success: true, profile });
  });

  // 1e. Dedicated Activity Log Page Endpoint (/api/admin/activity)
  app.get('/api/admin/activity', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const win = resolveDateRangeWindow(req.query);
    const search = String(req.query.q || '').trim().toLowerCase();
    const platformFilter = String(req.query.platform || 'all').trim().toLowerCase();
    const categoryFilter = String(req.query.category || 'all').trim().toLowerCase();
    const eventTypeFilter = String(req.query.event_type || 'all').trim().toLowerCase();
    const statusFilter = String(req.query.status || 'all').trim().toLowerCase();
    const ipVersionFilter = String(req.query.ip_version || 'all').trim();
    const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
    const pageSize = Math.min(100, Math.max(10, parseInt(String(req.query.page_size || '30'), 10) || 30));

    const allEvents = readJsonlTail<ActivityEventRecord>(ACTIVITY_LOG_FILE, 10000).reverse();

    const filtered = allEvents.filter(ev => {
      const t = Date.parse(ev.timestamp);
      if (!Number.isNaN(t) && (t < win.startMs || t > win.endMs)) return false;
      if (platformFilter !== 'all' && ev.platform !== platformFilter) return false;
      if (categoryFilter !== 'all' && ev.event_category !== categoryFilter) return false;
      if (eventTypeFilter !== 'all' && ev.event_type !== eventTypeFilter) return false;
      if (statusFilter !== 'all' && ev.status !== statusFilter) return false;
      if (ipVersionFilter !== 'all' && ev.ip_version !== ipVersionFilter) return false;
      if (search) {
        const hay = `${ev.event_id} ${ev.visitor_id} ${ev.session_id} ${ev.ip_address} ${ev.ip_hash} ${ev.request_id} ${ev.normalized_hostname} ${ev.event_type} ${ev.error_category || ''} ${ev.detail || ''}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    const total = filtered.length;
    const items = filtered.slice((page - 1) * pageSize, page * pageSize);

    // Breakdown counters for current filtered set
    const countsByCategory: Record<string, number> = {};
    const countsByStatus: Record<string, number> = {};
    for (const ev of filtered) {
      countsByCategory[ev.event_category] = (countsByCategory[ev.event_category] || 0) + 1;
      countsByStatus[ev.status] = (countsByStatus[ev.status] || 0) + 1;
    }

    return res.json({
      success: true,
      window: { preset: win.preset, start_date: win.startDateStr, end_date: win.endDateStr },
      total,
      page,
      page_size: pageSize,
      counts_by_category: countsByCategory,
      counts_by_status: countsByStatus,
      items
    });
  });

  // 1f. Activity Event Detail & Correlated Lifecycle View (/api/admin/activity/:id)
  app.get('/api/admin/activity/:id', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const eventId = String(req.params.id || '').trim();
    const allEvents = readJsonlTail<ActivityEventRecord>(ACTIVITY_LOG_FILE, 10000);
    const event = allEvents.find(e => e.event_id === eventId);
    if (!event) {
      return res.status(404).json({ success: false, error: 'Activity event not found.' });
    }
    const correlatedByRequest = event.request_id
      ? allEvents.filter(e => e.request_id === event.request_id)
      : [];
    const visitorProfile = visitorsMap.get(event.visitor_id) || null;

    return res.json({
      success: true,
      event,
      correlated_request_events: correlatedByRequest,
      visitor_profile: visitorProfile
    });
  });

  // 1g. CSV Exports for Visitors & Activity Logs
  app.get('/api/admin/export/visitors.csv', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const rows = Array.from(visitorsMap.values());
    const escapeCsv = (val: unknown) => `"${String(val ?? '').replace(/\r?\n/g, ' ').replace(/"/g, '""')}"`;

    const lines = [
      [
        'visitor_id',
        'first_seen_at',
        'last_active_at',
        'session_count',
        'last_ip',
        'ip_version',
        'links_submitted',
        'download_attempts',
        'successful_downloads',
        'client_confirmed_downloads',
        'failed_downloads',
        'most_used_platform',
        'device_category',
        'user_agent_summary',
        'blocked'
      ].join(',')
    ];
    for (const r of rows) {
      lines.push([
        escapeCsv(r.visitor_id),
        escapeCsv(r.first_seen_at),
        escapeCsv(r.last_active_at),
        escapeCsv(r.session_count),
        escapeCsv(r.last_ip),
        escapeCsv(r.ip_version),
        escapeCsv(r.links_submitted),
        escapeCsv(r.download_attempts),
        escapeCsv(r.successful_downloads),
        escapeCsv(r.client_confirmed_downloads || 0),
        escapeCsv(r.failed_downloads),
        escapeCsv(r.most_used_platform),
        escapeCsv(r.device_category),
        escapeCsv(r.user_agent_summary),
        escapeCsv(r.blocked)
      ].join(','));
    }

    recordAuditLog({
      actor: session.username,
      action: 'csv_export_visitors',
      target: `${rows.length}_visitors`,
      req,
      status: 'success',
      detail: `Exported ${rows.length} visitor profiles to CSV.`
    });

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="downdouyin-visitors-${new Date().toISOString().slice(0, 10)}.csv"`);
    return res.send('\uFEFF' + lines.join('\n') + '\n');
  });

  app.get('/api/admin/export/activity.csv', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const records = readJsonlTail<ActivityEventRecord>(ACTIVITY_LOG_FILE, 5000).reverse();
    const escapeCsv = (val: unknown) => `"${String(val ?? '').replace(/\r?\n/g, ' ').replace(/"/g, '""')}"`;

    const lines = [
      [
        'timestamp',
        'event_id',
        'visitor_id',
        'session_id',
        'ip_address',
        'ip_version',
        'event_category',
        'event_type',
        'status',
        'platform',
        'normalized_hostname',
        'valid_url',
        'download_initiated',
        'download_stage',
        'request_id',
        'duration_ms',
        'error_category',
        'detail'
      ].join(',')
    ];
    for (const r of records) {
      lines.push([
        escapeCsv(r.timestamp),
        escapeCsv(r.event_id),
        escapeCsv(r.visitor_id),
        escapeCsv(r.session_id),
        escapeCsv(r.ip_address),
        escapeCsv(r.ip_version),
        escapeCsv(r.event_category),
        escapeCsv(r.event_type),
        escapeCsv(r.status),
        escapeCsv(r.platform),
        escapeCsv(r.normalized_hostname),
        escapeCsv(r.valid_url ?? ''),
        escapeCsv(r.download_initiated),
        escapeCsv(r.download_stage || ''),
        escapeCsv(r.request_id),
        escapeCsv(r.duration_ms ?? ''),
        escapeCsv(r.error_category || ''),
        escapeCsv(r.detail || '')
      ].join(','));
    }

    recordAuditLog({
      actor: session.username,
      action: 'csv_export_activity',
      target: `${records.length}_events`,
      req,
      status: 'success',
      detail: `Exported ${records.length} activity log events to CSV.`
    });

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="downdouyin-activity-${new Date().toISOString().slice(0, 10)}.csv"`);
    return res.send('\uFEFF' + lines.join('\n') + '\n');
  });

  // 1h. Upgrade & Pricing Admin Management (/api/admin/pricing)
  app.get('/api/admin/pricing', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    return res.json({
      success: true,
      pricing: adminSettings.pricing_config || DEFAULT_PRICING_CONFIG
    });
  });

  app.put('/api/admin/pricing', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const current = adminSettings.pricing_config || { ...DEFAULT_PRICING_CONFIG };
    const b = req.body || {};

    const updated: UpgradePricingConfig = {
      enabled: typeof b.enabled === 'boolean' ? b.enabled : current.enabled,
      badge_text: typeof b.badge_text === 'string' ? b.badge_text.trim().slice(0, 48) : current.badge_text,
      headline_en: typeof b.headline_en === 'string' ? b.headline_en.trim().slice(0, 120) : current.headline_en,
      headline_zh: typeof b.headline_zh === 'string' ? b.headline_zh.trim().slice(0, 120) : current.headline_zh,
      subheadline_en: typeof b.subheadline_en === 'string' ? b.subheadline_en.trim().slice(0, 240) : current.subheadline_en,
      subheadline_zh: typeof b.subheadline_zh === 'string' ? b.subheadline_zh.trim().slice(0, 240) : current.subheadline_zh,
      free_plan: {
        name_en: typeof b.free_plan?.name_en === 'string' ? b.free_plan.name_en.trim().slice(0, 60) : current.free_plan.name_en,
        name_zh: typeof b.free_plan?.name_zh === 'string' ? b.free_plan.name_zh.trim().slice(0, 60) : current.free_plan.name_zh,
        price_label: typeof b.free_plan?.price_label === 'string' ? b.free_plan.price_label.trim().slice(0, 40) : current.free_plan.price_label,
        status_badge_en: typeof b.free_plan?.status_badge_en === 'string' ? b.free_plan.status_badge_en.trim().slice(0, 40) : current.free_plan.status_badge_en,
        status_badge_zh: typeof b.free_plan?.status_badge_zh === 'string' ? b.free_plan.status_badge_zh.trim().slice(0, 40) : current.free_plan.status_badge_zh,
        features_en: Array.isArray(b.free_plan?.features_en) ? b.free_plan.features_en.map((s: any) => String(s).trim().slice(0, 120)).filter(Boolean).slice(0, 8) : current.free_plan.features_en,
        features_zh: Array.isArray(b.free_plan?.features_zh) ? b.free_plan.features_zh.map((s: any) => String(s).trim().slice(0, 120)).filter(Boolean).slice(0, 8) : current.free_plan.features_zh
      },
      pro_plan: {
        name_en: typeof b.pro_plan?.name_en === 'string' ? b.pro_plan.name_en.trim().slice(0, 60) : current.pro_plan.name_en,
        name_zh: typeof b.pro_plan?.name_zh === 'string' ? b.pro_plan.name_zh.trim().slice(0, 60) : current.pro_plan.name_zh,
        price_label: typeof b.pro_plan?.price_label === 'string' ? b.pro_plan.price_label.trim().slice(0, 40) : current.pro_plan.price_label,
        status_badge_en: typeof b.pro_plan?.status_badge_en === 'string' ? b.pro_plan.status_badge_en.trim().slice(0, 40) : current.pro_plan.status_badge_en,
        status_badge_zh: typeof b.pro_plan?.status_badge_zh === 'string' ? b.pro_plan.status_badge_zh.trim().slice(0, 40) : current.pro_plan.status_badge_zh,
        coming_soon: typeof b.pro_plan?.coming_soon === 'boolean' ? b.pro_plan.coming_soon : current.pro_plan.coming_soon,
        features_en: Array.isArray(b.pro_plan?.features_en) ? b.pro_plan.features_en.map((s: any) => String(s).trim().slice(0, 120)).filter(Boolean).slice(0, 8) : current.pro_plan.features_en,
        features_zh: Array.isArray(b.pro_plan?.features_zh) ? b.pro_plan.features_zh.map((s: any) => String(s).trim().slice(0, 120)).filter(Boolean).slice(0, 8) : current.pro_plan.features_zh,
        cta_label_en: typeof b.pro_plan?.cta_label_en === 'string' ? b.pro_plan.cta_label_en.trim().slice(0, 60) : current.pro_plan.cta_label_en,
        cta_label_zh: typeof b.pro_plan?.cta_label_zh === 'string' ? b.pro_plan.cta_label_zh.trim().slice(0, 60) : current.pro_plan.cta_label_zh
      },
      contact_cta_enabled: typeof b.contact_cta_enabled === 'boolean' ? b.contact_cta_enabled : current.contact_cta_enabled,
      updated_at: new Date().toISOString()
    };

    adminSettings.pricing_config = updated;
    saveAdminSettings();

    recordAuditLog({
      actor: session.username,
      action: 'pricing_config_updated',
      target: 'upgrade_pricing_modal',
      req,
      status: 'success',
      detail: `Updated public Upgrade & Pricing configuration (coming_soon=${updated.pro_plan.coming_soon}).`
    });

    return res.json({ success: true, pricing: updated });
  });

  // 2. Website Analytics (/api/admin/analytics)
  app.get('/api/admin/analytics', requireAdminAuth('viewer'), async (req: Request, res: Response) => {
    const win = resolveDateRangeWindow(req.query);
    const allVisitors = readJsonlTail<VisitorTelemetryEvent>(VISITOR_LOG_FILE, 10000);
    const allDownloads = readJsonlTail<DownloadStatRecord>(STATS_LOG_FILE, 10000);
    const allFunnel = readJsonlTail<ContactFunnelEvent>(CONTACT_FUNNEL_FILE, 5000);

    const inRange = (iso: string) => {
      const t = Date.parse(iso);
      return !Number.isNaN(t) && t >= win.startMs && t <= win.endMs;
    };

    const periodVisitors = allVisitors.filter(v => inRange(v.timestamp));
    const periodDownloads = allDownloads.filter(d => inRange(d.timestamp));
    const periodFunnel = allFunnel.filter(f => inRange(f.timestamp));

    const referrers: Record<string, number> = {};
    const devices: Record<string, number> = { desktop: 0, mobile: 0, tablet: 0 };
    const languages: Record<string, number> = { en: 0, zh: 0 };

    for (const v of periodVisitors) {
      if (v.event_type === 'page_view') {
        referrers[v.referrer_host] = (referrers[v.referrer_host] || 0) + 1;
        devices[v.device_category] = (devices[v.device_category] || 0) + 1;
        languages[v.lang] = (languages[v.lang] || 0) + 1;
      }
    }

    let ga4LiveReport: any = null;
    let ga4Error: string | null = null;
    const propId = (adminSettings.ga4_property_id || process.env.GA4_PROPERTY_ID || '').trim();
    if (propId && parseGoogleServiceAccount()) {
      try {
        const token = await getGoogleServiceAccountToken(['https://www.googleapis.com/auth/analytics.readonly']);
        if (token) {
          const gaResp = await fetch(
            `https://analyticsdata.googleapis.com/v1beta/properties/${encodeURIComponent(propId)}:runReport`,
            {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                dateRanges: [{ startDate: win.startDateStr, endDate: win.endDateStr }],
                dimensions: [{ name: 'sessionDefaultChannelGroup' }, { name: 'country' }],
                metrics: [
                  { name: 'activeUsers' },
                  { name: 'sessions' },
                  { name: 'screenPageViews' }
                ],
                limit: 25
              })
            }
          );
          if (gaResp.ok) {
            ga4LiveReport = await gaResp.json();
          } else {
            const errJson: any = await gaResp.json().catch(() => ({}));
            ga4Error = errJson?.error?.message || `GA4 Data API returned HTTP ${gaResp.status}`;
          }
        }
      } catch (err: any) {
        ga4Error = sanitizeLogSummary(err?.message || 'GA4 Data API request failed');
      }
    }

    return res.json({
      success: true,
      window: { preset: win.preset, start_date: win.startDateStr, end_date: win.endDateStr },
      ga4_status: {
        frontend_tag_installed: true,
        measurement_id: adminSettings.ga4_measurement_id || 'G-S9BHCYX6EN',
        property_id_configured: Boolean(propId),
        service_account_configured: Boolean(parseGoogleServiceAccount()),
        data_api_active: Boolean(ga4LiveReport),
        data_api_error: ga4Error,
        tracked_client_events: [
          'page_view',
          'downloader_link_submit',
          'download_button_click',
          'download_request_started',
          'download_request_success',
          'download_request_failed'
        ]
      },
      ga4_report: ga4LiveReport,
      first_party_telemetry: {
        page_views: periodVisitors.filter(v => v.event_type === 'page_view').length,
        link_submits: periodDownloads.filter(d => d.operation === 'parse_request').length,
        download_button_clicks: periodVisitors.filter(v => v.event_type === 'download_click').length,
        completed_downloads: periodDownloads.filter(d => d.operation !== 'parse_request' && d.status === 'success').length,
        failed_downloads: periodDownloads.filter(d => d.operation !== 'parse_request' && d.status === 'failed').length,
        contact_form_opens: periodFunnel.filter(f => f.event_type === 'form_opened').length,
        contact_attempts: periodFunnel.filter(f => f.event_type === 'submission_attempted').length,
        contact_stored: periodFunnel.filter(f => f.event_type === 'submission_stored').length,
        referrers,
        devices,
        languages
      }
    });
  });

  // 3. Download Analytics & Platform Reports (/api/admin/downloads)
  app.get('/api/admin/downloads', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const win = resolveDateRangeWindow(req.query);
    const allRecords = readJsonlTail<DownloadStatRecord>(STATS_LOG_FILE, 10000);
    const allActivities = readJsonlTail<ActivityEventRecord>(ACTIVITY_LOG_FILE, 10000);

    const periodRecords = allRecords.filter(r => {
      const t = Date.parse(r.timestamp);
      return !Number.isNaN(t) && t >= win.startMs && t <= win.endMs;
    });
    const periodActivities = allActivities.filter(a => {
      const t = Date.parse(a.timestamp);
      return !Number.isNaN(t) && t >= win.startMs && t <= win.endMs;
    });

    const platforms: SupportedPlatform[] = ['douyin', 'bilibili', 'tiktok', 'xiaohongshu', 'unknown'];
    const byPlatform: Record<string, {
      parse_total: number;
      parse_success: number;
      parse_failed: number;
      download_total: number;
      download_success: number;
      download_failed: number;
      download_aborted: number;
      client_completed: number;
      avg_latency_ms: number;
      latency_sum: number;
      count: number;
    }> = {};

    for (const p of platforms) {
      byPlatform[p] = {
        parse_total: 0,
        parse_success: 0,
        parse_failed: 0,
        download_total: 0,
        download_success: 0,
        download_failed: 0,
        download_aborted: 0,
        client_completed: 0,
        avg_latency_ms: 0,
        latency_sum: 0,
        count: 0
      };
    }

    const describeErrorCategory = (cat: string): string => {
      const c = (cat || '').toLowerCase();
      if (c.includes('missing_sessdata') || c.includes('auth_cookie')) return 'Bilibili SESSDATA cookie missing or expired (1080p+/4K restricted)';
      if (c.includes('timeout')) return 'Upstream platform request timed out';
      if (c.includes('rate_limit') || c.includes('429')) return 'Rate-limited by upstream platform or anti-bot guard';
      if (c.includes('invalid_url') || c.includes('validation') || c.includes('unsupported')) return 'Invalid or unsupported share link submitted by visitor';
      if (c.includes('not_found') || c.includes('deleted') || c.includes('404')) return 'Video deleted, private, or unavailable on source platform';
      if (c.includes('stream_abort') || c.includes('client_closed')) return 'Visitor cancelled or closed browser during stream transfer';
      if (c.includes('upstream_403') || c.includes('forbidden')) return 'Upstream CDN rejected request (403 Forbidden / signature expired)';
      if (c.includes('upstream_error') || c.includes('parse_failed')) return 'Upstream parser structure changed or returned empty media stream';
      return cat.replace(/_/g, ' ');
    };

    const errorCategories: Record<string, number> = {};
    const errorReasonsDetailed: Array<{ category: string; count: number; description: string }> = [];
    let timeoutCount = 0;

    for (const r of periodRecords) {
      const b = byPlatform[r.platform] || byPlatform.unknown;
      b.count++;
      b.latency_sum += r.duration_ms || 0;
      if (r.operation === 'parse_request') {
        b.parse_total++;
        if (r.status === 'success') b.parse_success++;
        else b.parse_failed++;
      } else {
        b.download_total++;
        if (r.status === 'success') b.download_success++;
        else if (r.status === 'aborted') b.download_aborted++;
        else b.download_failed++;
      }
      if (r.status === 'failed' && r.error_category) {
        errorCategories[r.error_category] = (errorCategories[r.error_category] || 0) + 1;
        if (r.error_category.includes('timeout')) timeoutCount++;
      }
    }

    for (const [cat, count] of Object.entries(errorCategories).sort((a, b) => b[1] - a[1])) {
      errorReasonsDetailed.push({
        category: cat,
        count,
        description: describeErrorCategory(cat)
      });
    }

    // Lifecycle stage counts in window
    const stageCounts = {
      stage_1_request_processed: 0,
      stage_2_upstream_retrieved: 0,
      stage_3_stream_started: 0,
      stage_4_client_completed: 0
    };
    for (const a of periodActivities) {
      if (a.download_stage === '1_request_processed') stageCounts.stage_1_request_processed++;
      if (a.download_stage === '2_upstream_retrieved') stageCounts.stage_2_upstream_retrieved++;
      if (a.download_stage === '3_stream_started') stageCounts.stage_3_stream_started++;
      if (a.download_stage === '4_client_completed' || a.event_type === 'download_client_completed') {
        stageCounts.stage_4_client_completed++;
        const pb = byPlatform[a.platform] || byPlatform.unknown;
        if (pb) pb.client_completed++;
      }
    }

    for (const p of platforms) {
      const b = byPlatform[p];
      b.avg_latency_ms = b.count > 0 ? Math.round(b.latency_sum / b.count) : 0;
    }

    // Optional filtering and pagination for recent events & failures
    const platformFilter = String(req.query.platform || 'all').trim().toLowerCase();
    const statusFilter = String(req.query.status || 'all').trim().toLowerCase();
    const operationFilter = String(req.query.operation || 'all').trim().toLowerCase();
    const search = String(req.query.q || '').trim().toLowerCase();
    const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
    const pageSize = Math.min(100, Math.max(10, parseInt(String(req.query.page_size || '25'), 10) || 25));

    const filteredEvents = periodRecords.filter(r => {
      if (platformFilter !== 'all' && r.platform !== platformFilter) return false;
      if (statusFilter !== 'all' && r.status !== statusFilter) return false;
      if (operationFilter !== 'all' && r.operation !== operationFilter) return false;
      if (search) {
        const hay = `${r.request_id} ${r.platform} ${r.operation} ${r.download_method} ${r.error_category || ''} ${r.http_status}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    }).reverse();

    const recentFailures = periodRecords
      .filter(r => r.status === 'failed' && (platformFilter === 'all' || r.platform === platformFilter))
      .slice(-100)
      .reverse();

    const paginatedEvents = filteredEvents.slice((page - 1) * pageSize, page * pageSize);

    return res.json({
      success: true,
      window: { preset: win.preset, start_date: win.startDateStr, end_date: win.endDateStr, timezone: 'UTC' },
      total_events_in_window: periodRecords.length,
      filtered_total: filteredEvents.length,
      page,
      page_size: pageSize,
      timeout_count: timeoutCount,
      lifecycle_stages: stageCounts,
      by_platform: byPlatform,
      error_categories: errorCategories,
      error_reasons_detailed: errorReasonsDetailed,
      recent_failures: recentFailures,
      recent_events: paginatedEvents
    });
  });

  // 4. Contact Inbox & Feedback Management (/api/admin/contacts)
  app.get('/api/admin/contacts', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const rawRecords = readJsonlTail<RawContactRecord>(CONTACT_LOG_FILE, 5000);
    const funnelEvents = readJsonlTail<ContactFunnelEvent>(CONTACT_FUNNEL_FILE, 2000);

    const search = String(req.query.q || '').trim().toLowerCase();
    const statusFilter = String(req.query.status || 'all').trim().toLowerCase();
    const platformFilter = String(req.query.platform || 'all').trim().toLowerCase();
    const typeFilter = String(req.query.type || 'all').trim().toLowerCase();
    const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
    const pageSize = Math.min(100, Math.max(10, parseInt(String(req.query.page_size || '20'), 10) || 20));

    const enriched = rawRecords.map(r => {
      const st = getOrInitContactState(r);
      return {
        ...r,
        read: st.read,
        status: st.status,
        issue_type: st.issue_type,
        admin_notes: st.admin_notes,
        email_notification_status: st.email_notification_status,
        email_notification_at: st.email_notification_at,
        email_notification_error: st.email_notification_error,
        updated_at: st.updated_at,
        timeline: st.timeline
      };
    }).reverse();

    saveContactStates();

    const filtered = enriched.filter(item => {
      if (statusFilter !== 'all') {
        if (statusFilter === 'unread' && item.read) return false;
        if (statusFilter !== 'unread' && item.status !== statusFilter) return false;
      }
      if (platformFilter !== 'all' && item.platform !== platformFilter) return false;
      if (typeFilter !== 'all' && item.issue_type !== typeFilter && item.category !== typeFilter) return false;
      if (search) {
        const hay = `${item.inquiry_id} ${item.name} ${item.email} ${item.category} ${item.message}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    const total = filtered.length;
    const items = filtered.slice((page - 1) * pageSize, page * pageSize);

    const funnelSummary = {
      form_opened: funnelEvents.filter(e => e.event_type === 'form_opened').length,
      validation_failed: funnelEvents.filter(e => e.event_type === 'validation_failed').length,
      submission_attempted: funnelEvents.filter(e => e.event_type === 'submission_attempted').length,
      submission_stored: funnelEvents.filter(e => e.event_type === 'submission_stored').length,
      email_sent: funnelEvents.filter(e => e.event_type === 'email_sent').length,
      email_failed: funnelEvents.filter(e => e.event_type === 'email_failed').length,
      recent_attempts: funnelEvents.slice(-30).reverse()
    };

    return res.json({
      success: true,
      total,
      page,
      page_size: pageSize,
      items,
      funnel: funnelSummary
    });
  });

  // 4b. Update Contact Inquiry State
  app.patch('/api/admin/contacts/:id', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const inquiryId = String(req.params.id || '').trim();
    const rawRecords = readJsonlTail<RawContactRecord>(CONTACT_LOG_FILE, 5000);
    const target = rawRecords.find(r => r.inquiry_id === inquiryId);
    if (!target) {
      return res.status(404).json({ success: false, error: 'Inquiry record not found.' });
    }

    const state = getOrInitContactState(target);
    const nowIso = new Date().toISOString();
    const changes: string[] = [];

    if (typeof req.body?.read === 'boolean' && req.body.read !== state.read) {
      state.read = req.body.read;
      changes.push(`Marked as ${state.read ? 'read' : 'unread'}`);
    }
    if (typeof req.body?.status === 'string') {
      const newStatus = req.body.status as ContactInquiryStatus;
      if (['open', 'in_progress', 'resolved', 'spam'].includes(newStatus) && newStatus !== state.status) {
        state.status = newStatus;
        changes.push(`Status changed to ${newStatus}`);
      }
    }
    if (typeof req.body?.issue_type === 'string') {
      const newType = req.body.issue_type as ContactInquiryState['issue_type'];
      if (['inquiry', 'feedback', 'bug_report', 'other'].includes(newType) && newType !== state.issue_type) {
        state.issue_type = newType;
        changes.push(`Classification changed to ${newType}`);
      }
    }
    if (typeof req.body?.admin_notes === 'string') {
      state.admin_notes = req.body.admin_notes.trim().slice(0, 1000);
      changes.push('Updated internal notes');
    }

    if (changes.length > 0) {
      state.updated_at = nowIso;
      state.timeline.push({
        timestamp: nowIso,
        action: 'status_updated',
        actor: session.username,
        detail: changes.join('; ')
      });
      saveContactStates();

      recordAuditLog({
        actor: session.username,
        action: 'contact_inquiry_updated',
        target: inquiryId,
        req,
        status: 'success',
        detail: changes.join('; ')
      });
    }

    return res.json({ success: true, state });
  });

  // 4c. Delete Individual Contact Record
  app.delete('/api/admin/contacts/:id', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const inquiryId = String(req.params.id || '').trim();
    if (req.body?.confirm !== true) {
      return res.status(400).json({
        success: false,
        error: 'Explicit confirmation (confirm: true) is required to permanently delete a contact inquiry.'
      });
    }

    if (!fs.existsSync(CONTACT_LOG_FILE)) {
      return res.status(404).json({ success: false, error: 'Contact log file not found.' });
    }

    const lines = fs.readFileSync(CONTACT_LOG_FILE, 'utf8').split(/\r?\n/).filter(Boolean);
    const kept: string[] = [];
    let removed = false;
    for (const line of lines) {
      try {
        const parsed = JSON.parse(line) as RawContactRecord;
        if (parsed.inquiry_id === inquiryId) {
          removed = true;
          continue;
        }
      } catch {}
      kept.push(line);
    }

    if (!removed) {
      return res.status(404).json({ success: false, error: 'Inquiry record not found.' });
    }

    fs.writeFileSync(CONTACT_LOG_FILE, kept.join('\n') + (kept.length ? '\n' : ''), {
      encoding: 'utf8',
      mode: 0o600
    });
    delete contactStates[inquiryId];
    saveContactStates();

    recordAuditLog({
      actor: session.username,
      action: 'contact_inquiry_deleted',
      target: inquiryId,
      req,
      status: 'warning',
      detail: `Permanently deleted contact inquiry record #${inquiryId}.`
    });

    return res.json({ success: true, deleted_id: inquiryId });
  });

  // 4d. Export Authenticated Contact Records or Download Stats to CSV
  app.get('/api/admin/export/contacts.csv', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const rawRecords = readJsonlTail<RawContactRecord>(CONTACT_LOG_FILE, 5000);
    const idsFilter = typeof req.query.ids === 'string' && req.query.ids.trim()
      ? new Set(req.query.ids.split(',').map(s => s.trim()))
      : null;

    const rows = rawRecords.filter(r => !idsFilter || idsFilter.has(r.inquiry_id));
    const escapeCsv = (val: unknown) => {
      const s = String(val ?? '').replace(/\r?\n/g, ' ');
      return `"${s.replace(/"/g, '""')}"`;
    };

    const lines = [
      ['inquiry_id', 'timestamp', 'status', 'read', 'issue_type', 'category', 'platform', 'name', 'email', 'message'].join(',')
    ];
    for (const r of rows) {
      const st = getOrInitContactState(r);
      lines.push([
        escapeCsv(r.inquiry_id),
        escapeCsv(r.timestamp),
        escapeCsv(st.status),
        escapeCsv(st.read),
        escapeCsv(st.issue_type),
        escapeCsv(r.category),
        escapeCsv(r.platform),
        escapeCsv(r.name),
        escapeCsv(r.email),
        escapeCsv(r.message)
      ].join(','));
    }

    recordAuditLog({
      actor: session.username,
      action: 'csv_export_contacts',
      target: `${rows.length}_records`,
      req,
      status: 'success',
      detail: `Exported ${rows.length} contact inquiry records to CSV.`
    });

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="downdouyin-contacts-${new Date().toISOString().slice(0, 10)}.csv"`);
    return res.send('\uFEFF' + lines.join('\n') + '\n');
  });

  app.get('/api/admin/export/downloads.csv', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const records = readJsonlTail<DownloadStatRecord>(STATS_LOG_FILE, 5000);
    const escapeCsv = (val: unknown) => `"${String(val ?? '').replace(/"/g, '""')}"`;

    const lines = [
      ['timestamp', 'request_id', 'operation', 'platform', 'download_method', 'status', 'http_status', 'error_category', 'duration_ms'].join(',')
    ];
    for (const r of records) {
      lines.push([
        escapeCsv(r.timestamp),
        escapeCsv(r.request_id),
        escapeCsv(r.operation),
        escapeCsv(r.platform),
        escapeCsv(r.download_method),
        escapeCsv(r.status),
        escapeCsv(r.http_status),
        escapeCsv(r.error_category || ''),
        escapeCsv(r.duration_ms)
      ].join(','));
    }

    recordAuditLog({
      actor: session.username,
      action: 'csv_export_downloads',
      target: `${records.length}_records`,
      req,
      status: 'success',
      detail: `Exported ${records.length} operational download stat records to CSV.`
    });

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="downdouyin-downloads-${new Date().toISOString().slice(0, 10)}.csv"`);
    return res.send('\uFEFF' + lines.join('\n') + '\n');
  });

  // 5. Errors & Structured Logs (/api/admin/errors)
  app.get('/api/admin/errors', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const allErrors = readJsonlTail<AppErrorRecord>(ERRORS_LOG_FILE, 3000).reverse();
    const severityFilter = String(req.query.severity || 'all').trim().toLowerCase();
    const routeFilter = String(req.query.route || 'all').trim().toLowerCase();
    const platformFilter = String(req.query.platform || 'all').trim().toLowerCase();
    const search = String(req.query.q || '').trim().toLowerCase();
    const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
    const pageSize = Math.min(100, Math.max(10, parseInt(String(req.query.page_size || '25'), 10) || 25));

    const filtered = allErrors.filter(e => {
      if (severityFilter !== 'all' && e.severity !== severityFilter) return false;
      if (routeFilter !== 'all' && e.route_category !== routeFilter) return false;
      if (platformFilter !== 'all' && e.platform !== platformFilter) return false;
      if (search) {
        const hay = `${e.event_id} ${e.request_id} ${e.route_category} ${e.platform} ${e.error_category} ${e.summary} ${e.http_status}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    const byRoute: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    const byPlatform: Record<string, number> = {};
    const groupedMap = new Map<string, {
      signature: string;
      route_category: string;
      platform: string;
      error_category: string;
      severity: string;
      count: number;
      first_seen: string;
      last_seen: string;
      sample_summary: string;
      http_status: number;
    }>();

    for (const e of allErrors) {
      byRoute[e.route_category] = (byRoute[e.route_category] || 0) + 1;
      byCategory[e.error_category] = (byCategory[e.error_category] || 0) + 1;
      byPlatform[e.platform] = (byPlatform[e.platform] || 0) + 1;

      const sig = `${e.route_category}|${e.platform}|${e.error_category}`;
      const existing = groupedMap.get(sig);
      if (!existing) {
        groupedMap.set(sig, {
          signature: sig,
          route_category: e.route_category,
          platform: e.platform,
          error_category: e.error_category,
          severity: e.severity,
          count: 1,
          first_seen: e.timestamp,
          last_seen: e.timestamp,
          sample_summary: e.summary,
          http_status: e.http_status
        });
      } else {
        existing.count++;
        if (e.timestamp < existing.first_seen) existing.first_seen = e.timestamp;
        if (e.timestamp > existing.last_seen) {
          existing.last_seen = e.timestamp;
          existing.sample_summary = e.summary;
        }
      }
    }

    const groupedErrors = Array.from(groupedMap.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 25);

    const paginatedItems = filtered.slice((page - 1) * pageSize, page * pageSize);

    return res.json({
      success: true,
      total: filtered.length,
      total_unfiltered: allErrors.length,
      page,
      page_size: pageSize,
      retention_days: adminSettings.retention_days_operational_logs,
      by_route: byRoute,
      by_category: byCategory,
      by_platform: byPlatform,
      grouped_errors: groupedErrors,
      items: paginatedItems
    });
  });

  // 6. System Health & Storage Status (/api/admin/health)
  app.get('/api/admin/health', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const pkg = readJsonFileSafe<{ name?: string; version?: string }>(path.join(projectRoot, 'package.json'), {});
    const mem = process.memoryUsage();
    const backups = getBackupsList();
    const runtimeCfg = deps.getRuntimeConfigStatus();

    const getFileSize = (p: string) => {
      try {
        return fs.existsSync(p) ? fs.statSync(p).size : 0;
      } catch {
        return 0;
      }
    };

    // Disk space check via fs.statfsSync when available (Node 18.15+)
    let diskFreeMb: number | null = null;
    let diskTotalMb: number | null = null;
    let diskUsedPct: number | null = null;
    try {
      if (typeof (fs as any).statfsSync === 'function') {
        const stfs = (fs as any).statfsSync(logsDir);
        const blockSize = Number(stfs.bsize || 4096);
        const totalBytes = Number(stfs.blocks || 0) * blockSize;
        const availBytes = Number(stfs.bavail || stfs.bfree || 0) * blockSize;
        if (totalBytes > 0) {
          diskTotalMb = Math.round(totalBytes / (1024 * 1024));
          diskFreeMb = Math.round(availBytes / (1024 * 1024));
          diskUsedPct = Math.round(((totalBytes - availBytes) / totalBytes) * 1000) / 10;
        }
      }
    } catch {}

    const backupsTotalBytes = backups.reduce((acc, b) => acc + (b.size_bytes || 0), 0);
    const pm2Managed = Boolean(process.env.pm_id !== undefined || process.env.PM2_HOME || process.env.NODE_APP_INSTANCE !== undefined);

    return res.json({
      success: true,
      checked_at: new Date().toISOString(),
      application: {
        name: pkg.name || 'douyin-downloader',
        version: pkg.version || '1.0.0',
        node_version: process.version,
        platform_arch: `${process.platform}/${process.arch}`,
        pid: process.pid,
        pm2_managed: pm2Managed,
        pm2_id: process.env.pm_id ?? null,
        env_mode: process.env.NODE_ENV || 'development',
        port: Number(process.env.PORT || 3000),
        server_started_at: new Date(serverStartTime).toISOString(),
        uptime_seconds: Math.floor((Date.now() - serverStartTime) / 1000)
      },
      resources: {
        process_rss_mb: Math.round(mem.rss / (1024 * 1024)),
        heap_used_mb: Math.round(mem.heapUsed / (1024 * 1024)),
        heap_total_mb: Math.round(mem.heapTotal / (1024 * 1024)),
        system_total_ram_mb: Math.round(os.totalmem() / (1024 * 1024)),
        system_free_ram_mb: Math.round(os.freemem() / (1024 * 1024)),
        load_average_1m: Number((os.loadavg()[0] || 0).toFixed(2)),
        load_average_5m: Number((os.loadavg()[1] || 0).toFixed(2)),
        cpu_cores: os.cpus().length,
        disk_free_mb: diskFreeMb,
        disk_total_mb: diskTotalMb,
        disk_used_pct: diskUsedPct
      },
      storage: {
        mode: 'local_persistent_jsonl_and_atomic_json',
        logs_directory: logsDir,
        writable: (() => {
          try {
            fs.accessSync(logsDir, fs.constants.W_OK);
            return true;
          } catch {
            return false;
          }
        })(),
        files: {
          download_stats_bytes: getFileSize(STATS_LOG_FILE),
          activity_events_bytes: getFileSize(ACTIVITY_LOG_FILE),
          visitors_index_bytes: getFileSize(VISITORS_INDEX_FILE),
          contact_messages_bytes: getFileSize(CONTACT_LOG_FILE),
          app_errors_bytes: getFileSize(ERRORS_LOG_FILE),
          audit_log_bytes: getFileSize(AUDIT_LOG_FILE),
          visitor_events_bytes: getFileSize(VISITOR_LOG_FILE)
        },
        backups_count: backups.length,
        backups_total_bytes: backupsTotalBytes,
        last_backup: backups[0] || null
      },
      integrations: {
        resend_email_configured: isResendConfigured(),
        ga4_tag_configured: true,
        ga4_data_api_configured: Boolean(adminSettings.ga4_property_id && parseGoogleServiceAccount()),
        search_console_api_configured: Boolean(adminSettings.gsc_site_url && parseGoogleServiceAccount()),
        bilibili_cookie_configured: runtimeCfg.bilibiliConfigured,
        bilibili_cookie_source: runtimeCfg.bilibiliSource,
        tiktok_proxy_configured: runtimeCfg.tiktokProxyConfigured
      }
    });
  });

  // 7. SEO & Search Console Overview (/api/admin/seo)
  // Performs real HTTP loopback checks against the running Express routes (/ , /sitemap.xml , /robots.txt)
  app.get('/api/admin/seo', requireAdminAuth('viewer'), async (req: Request, res: Response) => {
    const indexPath = path.join(staticDir, 'index.html');
    const localPort = Number(process.env.PORT || 3000);
    const localBaseUrl = `http://127.0.0.1:${localPort}`;

    let html = '';
    let homepageHttpStatus = 0;
    let homepageLatencyMs = 0;

    try {
      const t0 = Date.now();
      const homeResp = await fetch(`${localBaseUrl}/`, {
        headers: { 'User-Agent': 'DownDouyin-SEO-Inspector/1.0' }
      });
      homepageHttpStatus = homeResp.status;
      homepageLatencyMs = Date.now() - t0;
      if (homeResp.ok) {
        html = await homeResp.text();
      }
    } catch {}

    if (!html) {
      try {
        if (fs.existsSync(indexPath)) html = fs.readFileSync(indexPath, 'utf8');
      } catch {}
    }

    // Live check /sitemap.xml route
    let sitemapHttpStatus = 0;
    let sitemapContentType = '';
    let sitemapXmlValid = false;
    let sitemapBody = '';
    let sitemapUrlCount = 0;
    let sitemapLatencyMs = 0;
    try {
      const t0 = Date.now();
      const smResp = await fetch(`${localBaseUrl}/sitemap.xml`, {
        headers: { 'User-Agent': 'DownDouyin-SEO-Inspector/1.0' }
      });
      sitemapHttpStatus = smResp.status;
      sitemapLatencyMs = Date.now() - t0;
      sitemapContentType = smResp.headers.get('content-type') || '';
      sitemapBody = await smResp.text();
      sitemapXmlValid =
        smResp.status === 200 &&
        sitemapContentType.toLowerCase().includes('xml') &&
        sitemapBody.includes('<urlset') &&
        sitemapBody.includes('<loc>https://downdouyin.com/</loc>');
      const locMatches = sitemapBody.match(/<loc>/g);
      sitemapUrlCount = locMatches ? locMatches.length : 0;
    } catch {}

    // Live check /robots.txt route
    let robotsHttpStatus = 0;
    let robotsContentType = '';
    let robotsBody = '';
    let robotsHasSitemapDirective = false;
    let robotsDisallowsAdmin = false;
    let robotsLatencyMs = 0;
    try {
      const t0 = Date.now();
      const rbResp = await fetch(`${localBaseUrl}/robots.txt`, {
        headers: { 'User-Agent': 'DownDouyin-SEO-Inspector/1.0' }
      });
      robotsHttpStatus = rbResp.status;
      robotsLatencyMs = Date.now() - t0;
      robotsContentType = rbResp.headers.get('content-type') || '';
      robotsBody = await rbResp.text();
      robotsHasSitemapDirective = /Sitemap:\s*https:\/\/downdouyin\.com\/sitemap\.xml/i.test(robotsBody);
      robotsDisallowsAdmin = /Disallow:\s*\/admin/i.test(robotsBody);
    } catch {}

    const extractTag = (regex: RegExp) => {
      const m = html.match(regex);
      return m ? m[1].trim() : null;
    };

    const title = extractTag(/<title>([^<]+)<\/title>/i);
    const metaDesc =
      extractTag(/<meta\s+name=["']description["']\s+content=["']([^"']+)["']/i) ||
      extractTag(/<meta\s+content=["']([^"']+)["']\s+name=["']description["']/i);
    const canonical =
      extractTag(/<link\s+rel=["']canonical["']\s+href=["']([^"']+)["']/i) ||
      extractTag(/<link\s+href=["']([^"']+)["']\s+rel=["']canonical["']/i);
    const metaRobots =
      extractTag(/<meta\s+name=["']robots["']\s+content=["']([^"']+)["']/i) ||
      extractTag(/<meta\s+content=["']([^"']+)["']\s+name=["']robots["']/i);
    const ogTitle =
      extractTag(/<meta\s+property=["']og:title["']\s+content=["']([^"']+)["']/i) ||
      extractTag(/<meta\s+content=["']([^"']+)["']\s+property=["']og:title["']/i);
    const ogDescription =
      extractTag(/<meta\s+property=["']og:description["']\s+content=["']([^"']+)["']/i) ||
      extractTag(/<meta\s+content=["']([^"']+)["']\s+property=["']og:description["']/i);
    const ogUrl =
      extractTag(/<meta\s+property=["']og:url["']\s+content=["']([^"']+)["']/i) ||
      extractTag(/<meta\s+content=["']([^"']+)["']\s+property=["']og:url["']/i);
    const ogImage =
      extractTag(/<meta\s+property=["']og:image["']\s+content=["']([^"']+)["']/i) ||
      extractTag(/<meta\s+content=["']([^"']+)["']\s+property=["']og:image["']/i);
    const twitterCard =
      extractTag(/<meta\s+name=["']twitter:card["']\s+content=["']([^"']+)["']/i) ||
      extractTag(/<meta\s+property=["']twitter:card["']\s+content=["']([^"']+)["']/i);
    const hasJsonLd = html.includes('application/ld+json');

    let gscReport: any = null;
    let gscError: string | null = null;
    const siteUrl = (adminSettings.gsc_site_url || process.env.GSC_SITE_URL || 'https://downdouyin.com/').trim();
    if (siteUrl && parseGoogleServiceAccount()) {
      try {
        const token = await getGoogleServiceAccountToken(['https://www.googleapis.com/auth/webmasters.readonly']);
        if (token) {
          const win = resolveDateRangeWindow(req.query);
          const gscResp = await fetch(
            `https://www.googleapis.com/webmasters/v3/sites/${encodeURIComponent(siteUrl)}/searchAnalytics/query`,
            {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                startDate: win.startDateStr,
                endDate: win.endDateStr,
                dimensions: ['query', 'page'],
                rowLimit: 20
              })
            }
          );
          if (gscResp.ok) {
            gscReport = await gscResp.json();
          } else {
            const errJson: any = await gscResp.json().catch(() => ({}));
            gscError = errJson?.error?.message || `Search Console API returned HTTP ${gscResp.status}`;
          }
        }
      } catch (err: any) {
        gscError = sanitizeLogSummary(err?.message || 'Search Console API request failed');
      }
    }

    const checkedAt = new Date().toISOString();

    return res.json({
      success: true,
      last_checked_at: checkedAt,
      technical_seo: {
        homepage_http_status: homepageHttpStatus,
        homepage_latency_ms: homepageLatencyMs,
        canonical_url: canonical || 'https://downdouyin.com/',
        canonical_valid: canonical === 'https://downdouyin.com/',
        https_enforced_in_canonical: Boolean(canonical && canonical.startsWith('https://downdouyin.com')),
        title,
        title_length: title ? title.length : 0,
        meta_description: metaDesc,
        meta_description_length: metaDesc ? metaDesc.length : 0,
        meta_robots: metaRobots,
        indexable: !metaRobots || !metaRobots.toLowerCase().includes('noindex'),
        og_title: ogTitle,
        og_description: ogDescription,
        og_url: ogUrl,
        og_image: ogImage,
        twitter_card: twitterCard,
        structured_data_json_ld: hasJsonLd,
        sitemap_endpoint: 'https://downdouyin.com/sitemap.xml',
        sitemap_http_status: sitemapHttpStatus,
        sitemap_content_type: sitemapContentType,
        sitemap_xml_valid: sitemapXmlValid,
        sitemap_url_count: sitemapUrlCount,
        sitemap_latency_ms: sitemapLatencyMs,
        sitemap_file_present: sitemapXmlValid,
        sitemap_content_preview: sitemapBody.slice(0, 1200),
        robots_endpoint: 'https://downdouyin.com/robots.txt',
        robots_http_status: robotsHttpStatus,
        robots_content_type: robotsContentType,
        robots_has_sitemap_directive: robotsHasSitemapDirective,
        robots_disallows_admin: robotsDisallowsAdmin,
        robots_latency_ms: robotsLatencyMs,
        robots_file_present: robotsHttpStatus === 200 && robotsBody.length > 0,
        robots_content: robotsBody
      },
      search_console: {
        site_url: siteUrl,
        service_account_configured: Boolean(parseGoogleServiceAccount()),
        api_active: Boolean(gscReport),
        api_error: gscError,
        report: gscReport
      }
    });
  });

  // 8. Email Notifications History & Test Email (/api/admin/notifications)
  app.get('/api/admin/notifications', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const deliveries = readJsonlTail<EmailDeliveryRecord>(EMAIL_LOG_FILE, 500).reverse();
    return res.json({
      success: true,
      provider: 'Resend (HTTPS API)',
      configured: isResendConfigured(),
      settings: {
        notification_to_email: adminSettings.notification_to_email,
        notification_from_email: adminSettings.notification_from_email,
        admin_alert_email: adminSettings.admin_alert_email,
        notify_on_contact: adminSettings.notify_on_contact,
        notify_on_feedback: adminSettings.notify_on_feedback,
        notify_on_app_errors: adminSettings.notify_on_app_errors,
        notify_on_repeated_failures: adminSettings.notify_on_repeated_failures,
        repeated_failure_threshold: adminSettings.repeated_failure_threshold,
        summary_schedule: adminSettings.summary_schedule
      },
      deliveries: deliveries.slice(0, 100)
    });
  });

  app.post('/api/admin/notifications/test', requireAdminAuth('admin'), async (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const recipient = String(req.body?.to || adminSettings.notification_to_email || adminSettings.admin_alert_email || '').trim();
    if (!recipient || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipient)) {
      return res.status(400).json({
        success: false,
        error: 'Please configure or provide a valid recipient email address first.'
      });
    }

    const result = await sendTransactionalEmail({
      eventType: 'test_email',
      to: recipient,
      subject: '[DownDouyin Admin] Test Notification Email',
      textBody: [
        'This is an administrator-initiated test email from the DownDouyin Admin Control Center.',
        `Initiated by: ${session.username}`,
        `Timestamp: ${new Date().toISOString()}`,
        'If you received this message, your Resend email integration is active and verified.'
      ].join('\n')
    });

    recordAuditLog({
      actor: session.username,
      action: 'send_test_email',
      target: recipient,
      req,
      status: result.sent ? 'success' : 'failed',
      detail: result.sent ? `Test email accepted by Resend (${result.providerId})` : `Test email failed: ${result.error}`
    });

    if (!result.sent) {
      return res.status(400).json({
        success: false,
        error: result.error || 'Failed to send test email.'
      });
    }
    return res.json({
      success: true,
      provider_id: result.providerId,
      recipient,
      sent_at: new Date().toISOString(),
      message: `Accepted by Resend API (Message ID: ${result.providerId || 'verified'}).`
    });
  });

  // 8b. Integrations Status & Live Verification (/api/admin/integrations)
  app.get('/api/admin/integrations', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const runtimeCfg = deps.getRuntimeConfigStatus();
    const sa = parseGoogleServiceAccount();
    return res.json({
      success: true,
      checked_at: new Date().toISOString(),
      integrations: {
        resend: {
          name: 'Resend Transactional Email API',
          configured: isResendConfigured(),
          from_email: adminSettings.notification_from_email || process.env.NOTIFICATION_FROM_EMAIL || 'onboarding@resend.dev',
          to_email: adminSettings.notification_to_email || adminSettings.admin_alert_email || process.env.NOTIFICATION_TO_EMAIL || ''
        },
        ga4: {
          name: 'Google Analytics 4',
          frontend_tag_installed: true,
          measurement_id: adminSettings.ga4_measurement_id || 'G-S9BHCYX6EN',
          property_id: adminSettings.ga4_property_id || process.env.GA4_PROPERTY_ID || '',
          service_account_configured: Boolean(sa),
          data_api_ready: Boolean((adminSettings.ga4_property_id || process.env.GA4_PROPERTY_ID) && sa)
        },
        gsc: {
          name: 'Google Search Console API',
          site_url: adminSettings.gsc_site_url || process.env.GSC_SITE_URL || 'https://downdouyin.com/',
          service_account_configured: Boolean(sa),
          api_ready: Boolean((adminSettings.gsc_site_url || process.env.GSC_SITE_URL) && sa)
        },
        bilibili: {
          name: 'Bilibili High-Res Extractor (1080p+/4K)',
          cookie_configured: runtimeCfg.bilibiliConfigured,
          source: runtimeCfg.bilibiliSource
        },
        tiktok: {
          name: 'TikTok Extractor & Optional Proxy',
          proxy_configured: runtimeCfg.tiktokProxyConfigured
        }
      }
    });
  });

  app.post('/api/admin/integrations/test', requireAdminAuth('admin'), async (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const service = String(req.body?.service || '').trim().toLowerCase();
    const runtimeCfg = deps.getRuntimeConfigStatus();
    const checkedAt = new Date().toISOString();

    if (service === 'bilibili') {
      try {
        const t0 = Date.now();
        const resp = await fetch('https://api.bilibili.com/x/web-interface/nav', {
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        });
        const latencyMs = Date.now() - t0;
        const ok = resp.status === 200;
        recordAuditLog({
          actor: session.username,
          action: 'integration_test_bilibili',
          target: 'bilibili',
          req,
          status: ok ? 'success' : 'warning',
          detail: `Tested Bilibili API connectivity (HTTP ${resp.status}, ${latencyMs}ms, SESSDATA configured: ${runtimeCfg.bilibiliConfigured}).`
        });
        return res.json({
          success: true,
          service: 'bilibili',
          checked_at: checkedAt,
          reachable: ok,
          cookie_configured: runtimeCfg.bilibiliConfigured,
          cookie_source: runtimeCfg.bilibiliSource,
          latency_ms: latencyMs,
          message: runtimeCfg.bilibiliConfigured
            ? `Bilibili API reachable (${latencyMs}ms) and SESSDATA cookie is configured via ${runtimeCfg.bilibiliSource}.`
            : `Bilibili public API reachable (${latencyMs}ms). Note: SESSDATA cookie is not configured, so streams default to standard 360p/720p quality.`
        });
      } catch (err: any) {
        return res.status(400).json({
          success: false,
          error: `Bilibili connectivity check failed: ${sanitizeLogSummary(err?.message || 'Network error')}`
        });
      }
    }

    if (service === 'tiktok') {
      try {
        const t0 = Date.now();
        const resp = await fetch('https://www.tikwm.com/api/', {
          method: 'HEAD',
          headers: { 'User-Agent': 'Mozilla/5.0' }
        }).catch(() => null);
        const latencyMs = Date.now() - t0;
        const ok = Boolean(resp && resp.status < 500);
        recordAuditLog({
          actor: session.username,
          action: 'integration_test_tiktok',
          target: 'tiktok',
          req,
          status: ok ? 'success' : 'warning',
          detail: `Tested TikTok upstream reachability (${latencyMs}ms, proxy configured: ${runtimeCfg.tiktokProxyConfigured}).`
        });
        return res.json({
          success: true,
          service: 'tiktok',
          checked_at: checkedAt,
          reachable: ok,
          proxy_configured: runtimeCfg.tiktokProxyConfigured,
          latency_ms: latencyMs,
          message: ok
            ? `TikTok upstream extractor reachable (${latencyMs}ms). Custom proxy: ${runtimeCfg.tiktokProxyConfigured ? 'Configured' : 'Direct connection (no proxy needed)'}.`
            : 'TikTok upstream check returned an unexpected response.'
        });
      } catch (err: any) {
        return res.status(400).json({
          success: false,
          error: `TikTok connectivity check failed: ${sanitizeLogSummary(err?.message || 'Network error')}`
        });
      }
    }

    return res.status(400).json({
      success: false,
      error: 'Unsupported integration test target. Supported values: bilibili, tiktok.'
    });
  });

  // 9. Security & Audit Log (/api/admin/audit)
  app.get('/api/admin/audit', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const allLogs = readJsonlTail<AuditLogRecord>(AUDIT_LOG_FILE, 2000).reverse();
    const search = String(req.query.q || '').trim().toLowerCase();
    const actionFilter = String(req.query.action || 'all').trim().toLowerCase();
    const statusFilter = String(req.query.status || 'all').trim().toLowerCase();
    const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1);
    const pageSize = Math.min(100, Math.max(10, parseInt(String(req.query.page_size || '50'), 10) || 50));

    const filteredLogs = allLogs.filter(l => {
      if (actionFilter !== 'all' && l.action.toLowerCase() !== actionFilter) return false;
      if (statusFilter !== 'all' && l.status.toLowerCase() !== statusFilter) return false;
      if (search) {
        const hay = `${l.actor} ${l.action} ${l.target} ${l.detail || ''} ${l.ip_hash}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      return true;
    });

    const activeSessionsList = Array.from(activeSessions.values()).map(s => ({
      session_ref: getSessionRef(s.sid_hash),
      username: s.username,
      role: s.role,
      created_at: new Date(s.created_at).toISOString(),
      last_active_at: new Date(s.last_active_at).toISOString(),
      expires_at: new Date(s.expires_at).toISOString(),
      user_agent_summary: s.user_agent_summary,
      ip_summary: s.sid_hash.slice(0, 10),
      is_current: s.sid_hash === (req as any).adminSession?.sid_hash
    }));

    return res.json({
      success: true,
      active_sessions: activeSessionsList,
      users: adminUsers.map(u => ({
        id: u.id,
        username: u.username,
        email: u.email,
        role: u.role,
        created_at: u.created_at,
        last_login_at: u.last_login_at,
        disabled: u.disabled
      })),
      total_audit_logs: filteredLogs.length,
      page,
      page_size: pageSize,
      audit_logs: filteredLogs.slice((page - 1) * pageSize, page * pageSize)
    });
  });

  // 10. Settings & Backups (/api/admin/settings, /api/admin/backups)
  app.get('/api/admin/settings', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    return res.json({
      success: true,
      settings: {
        notification_to_email: adminSettings.notification_to_email,
        notification_from_email: adminSettings.notification_from_email,
        admin_alert_email: adminSettings.admin_alert_email,
        notify_on_contact: adminSettings.notify_on_contact,
        notify_on_feedback: adminSettings.notify_on_feedback,
        notify_on_app_errors: adminSettings.notify_on_app_errors,
        notify_on_repeated_failures: adminSettings.notify_on_repeated_failures,
        repeated_failure_threshold: adminSettings.repeated_failure_threshold,
        summary_schedule: adminSettings.summary_schedule,
        shortcut_enabled: adminSettings.shortcut_enabled,
        shortcut_configured: Boolean(adminSettings.shortcut_phrase_hash),
        shortcut_updated_at: adminSettings.shortcut_updated_at,
        ga4_measurement_id: adminSettings.ga4_measurement_id,
        ga4_property_id: adminSettings.ga4_property_id,
        gsc_site_url: adminSettings.gsc_site_url,
        retention_days_operational_logs: adminSettings.retention_days_operational_logs,
        retention_days_contact_messages: adminSettings.retention_days_contact_messages,
        session_ttl_hours: adminSettings.session_ttl_hours,
        ip_logging_mode: adminSettings.ip_logging_mode || 'full',
        updated_at: adminSettings.updated_at
      },
      backups: getBackupsList()
    });
  });

  app.put('/api/admin/settings', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const b = req.body || {};

    if (typeof b.notification_to_email === 'string') {
      adminSettings.notification_to_email = b.notification_to_email.trim().slice(0, 120);
    }
    if (typeof b.notification_from_email === 'string') {
      adminSettings.notification_from_email = b.notification_from_email.trim().slice(0, 120);
    }
    if (typeof b.admin_alert_email === 'string') {
      adminSettings.admin_alert_email = b.admin_alert_email.trim().slice(0, 120);
    }
    if (typeof b.notify_on_contact === 'boolean') adminSettings.notify_on_contact = b.notify_on_contact;
    if (typeof b.notify_on_feedback === 'boolean') adminSettings.notify_on_feedback = b.notify_on_feedback;
    if (typeof b.notify_on_app_errors === 'boolean') adminSettings.notify_on_app_errors = b.notify_on_app_errors;
    if (typeof b.notify_on_repeated_failures === 'boolean') {
      adminSettings.notify_on_repeated_failures = b.notify_on_repeated_failures;
    }
    if (Number.isFinite(Number(b.repeated_failure_threshold))) {
      adminSettings.repeated_failure_threshold = Math.max(2, Math.min(100, Number(b.repeated_failure_threshold)));
    }
    if (b.summary_schedule === 'off' || b.summary_schedule === 'daily' || b.summary_schedule === 'weekly') {
      adminSettings.summary_schedule = b.summary_schedule;
    }
    if (b.ip_logging_mode === 'full' || b.ip_logging_mode === 'masked' || b.ip_logging_mode === 'hashed') {
      adminSettings.ip_logging_mode = b.ip_logging_mode;
    }
    if (typeof b.shortcut_enabled === 'boolean') {
      adminSettings.shortcut_enabled = b.shortcut_enabled;
    }
    if (typeof b.new_shortcut_phrase === 'string') {
      const phrase = b.new_shortcut_phrase.trim();
      if (phrase === '') {
        adminSettings.shortcut_phrase_hash = null;
        adminSettings.shortcut_enabled = false;
      } else if (phrase.length >= 4 && phrase.length <= 64) {
        adminSettings.shortcut_phrase_hash = sha256Hex(phrase);
        adminSettings.shortcut_updated_at = new Date().toISOString();
      } else {
        return res.status(400).json({
          success: false,
          error: 'Shortcut phrase must be between 4 and 64 characters.'
        });
      }
    }
    if (typeof b.ga4_measurement_id === 'string') {
      adminSettings.ga4_measurement_id = b.ga4_measurement_id.trim().slice(0, 32);
    }
    if (typeof b.ga4_property_id === 'string') {
      adminSettings.ga4_property_id = b.ga4_property_id.trim().replace(/[^0-9]/g, '').slice(0, 24);
    }
    if (typeof b.gsc_site_url === 'string') {
      adminSettings.gsc_site_url = b.gsc_site_url.trim().slice(0, 120);
    }
    if (Number.isFinite(Number(b.retention_days_operational_logs))) {
      adminSettings.retention_days_operational_logs = Math.max(7, Math.min(3650, Number(b.retention_days_operational_logs)));
    }
    if (Number.isFinite(Number(b.retention_days_contact_messages))) {
      adminSettings.retention_days_contact_messages = Math.max(30, Math.min(3650, Number(b.retention_days_contact_messages)));
    }
    if (Number.isFinite(Number(b.session_ttl_hours))) {
      adminSettings.session_ttl_hours = Math.max(1, Math.min(168, Number(b.session_ttl_hours)));
    }

    saveAdminSettings();

    recordAuditLog({
      actor: session.username,
      action: 'admin_settings_updated',
      target: 'admin_settings',
      req,
      status: 'success',
      detail: 'Updated administrator settings and notification/shortcut preferences.'
    });

    return res.json({ success: true, updated_at: adminSettings.updated_at });
  });

  // 10b. Create Snapshot Backup (Verifies integrity on disk and excludes secrets)
  app.post('/api/admin/backups/create', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `backup-${stamp}.json`;
    const dest = path.join(backupsDir, filename);

    const safeSettings = {
      ...adminSettings,
      shortcut_phrase_hash: adminSettings.shortcut_phrase_hash ? '[REDACTED_SHA256_HASH]' : null
    };

    const payload = {
      schema_version: 2,
      created_at: new Date().toISOString(),
      created_by: session.username,
      settings: safeSettings,
      contact_inquiries: readJsonlTail<RawContactRecord>(CONTACT_LOG_FILE, 5000),
      contact_states: contactStates,
      visitors_count: visitorsMap.size,
      download_stats_summary: deps.getDownloadStats().summary
    };

    try {
      writeJsonFileAtomic(dest, payload);
      if (!fs.existsSync(dest)) {
        throw new Error('Backup file was not found on disk after write.');
      }
      const st = fs.statSync(dest);
      if (st.size <= 10) {
        throw new Error('Backup file is unexpectedly empty.');
      }
      // Verify JSON parse integrity
      const verifyParsed = JSON.parse(fs.readFileSync(dest, 'utf8'));
      if (!verifyParsed || !verifyParsed.created_at) {
        throw new Error('Backup JSON verification failed.');
      }

      recordAuditLog({
        actor: session.username,
        action: 'backup_created',
        target: filename,
        req,
        status: 'success',
        detail: `Created & verified operational snapshot backup (${st.size} bytes).`
      });

      return res.json({
        success: true,
        backup: {
          backup_id: filename.replace(/\.json$/, ''),
          filename,
          created_at: st.mtime.toISOString(),
          size_bytes: st.size,
          created_by: session.username
        },
        backups: getBackupsList()
      });
    } catch (err: any) {
      recordAuditLog({
        actor: session.username,
        action: 'backup_failed',
        target: filename,
        req,
        status: 'failed',
        detail: `Backup creation failed: ${sanitizeLogSummary(err?.message || 'Disk write error')}`
      });
      return res.status(500).json({
        success: false,
        error: `Backup creation failed: ${sanitizeLogSummary(err?.message || 'Unable to write backup file')}`
      });
    }
  });

  // 10c. Download Snapshot Backup File Safely
  app.get('/api/admin/backups/:filename/download', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const rawName = String(req.params.filename || '').trim();
    if (!/^backup-[a-zA-Z0-9_-]+\.json$/.test(rawName)) {
      return res.status(400).json({ success: false, error: 'Invalid backup filename format.' });
    }
    const targetPath = path.resolve(backupsDir, rawName);
    if (!targetPath.startsWith(path.resolve(backupsDir) + path.sep) || !fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, error: 'Backup snapshot not found.' });
    }

    recordAuditLog({
      actor: session.username,
      action: 'backup_downloaded',
      target: rawName,
      req,
      status: 'success',
      detail: `Downloaded backup snapshot ${rawName}.`
    });

    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${rawName}"`);
    return res.sendFile(targetPath);
  });

  // 10d. Restore Settings & Contact State from Snapshot Backup (Owner only, creates pre-restore safety snapshot first)
  app.post('/api/admin/backups/:filename/restore', requireAdminAuth('owner'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    if (req.body?.confirm !== true) {
      return res.status(400).json({
        success: false,
        error: 'Explicit confirmation (confirm: true) is required to restore from a backup snapshot.'
      });
    }
    const rawName = String(req.params.filename || '').trim();
    if (!/^backup-[a-zA-Z0-9_-]+\.json$/.test(rawName)) {
      return res.status(400).json({ success: false, error: 'Invalid backup filename format.' });
    }
    const targetPath = path.resolve(backupsDir, rawName);
    if (!targetPath.startsWith(path.resolve(backupsDir) + path.sep) || !fs.existsSync(targetPath)) {
      return res.status(404).json({ success: false, error: 'Backup snapshot not found.' });
    }

    try {
      const parsed = JSON.parse(fs.readFileSync(targetPath, 'utf8'));
      if (!parsed || typeof parsed !== 'object' || !parsed.settings) {
        return res.status(400).json({ success: false, error: 'Backup file structure is invalid or corrupted.' });
      }

      // Create automatic pre-restore safety backup first
      const preStamp = new Date().toISOString().replace(/[:.]/g, '-');
      const preFilename = `backup-prerestore-${preStamp}.json`;
      writeJsonFileAtomic(path.join(backupsDir, preFilename), {
        schema_version: 2,
        created_at: new Date().toISOString(),
        created_by: `${session.username} (auto-prerestore)`,
        settings: {
          ...adminSettings,
          shortcut_phrase_hash: adminSettings.shortcut_phrase_hash ? '[REDACTED_SHA256_HASH]' : null
        },
        contact_states: contactStates
      });

      // Restore non-secret settings safely
      const s = parsed.settings;
      if (typeof s.notification_to_email === 'string') adminSettings.notification_to_email = s.notification_to_email;
      if (typeof s.notification_from_email === 'string') adminSettings.notification_from_email = s.notification_from_email;
      if (typeof s.admin_alert_email === 'string') adminSettings.admin_alert_email = s.notification_alert_email || s.admin_alert_email;
      if (typeof s.notify_on_contact === 'boolean') adminSettings.notify_on_contact = s.notify_on_contact;
      if (typeof s.notify_on_feedback === 'boolean') adminSettings.notify_on_feedback = s.notify_on_feedback;
      if (typeof s.notify_on_app_errors === 'boolean') adminSettings.notify_on_app_errors = s.notify_on_app_errors;
      if (typeof s.notify_on_repeated_failures === 'boolean') adminSettings.notify_on_repeated_failures = s.notify_on_repeated_failures;
      if (Number.isFinite(Number(s.repeated_failure_threshold))) adminSettings.repeated_failure_threshold = Number(s.repeated_failure_threshold);
      if (s.summary_schedule === 'off' || s.summary_schedule === 'daily' || s.summary_schedule === 'weekly') adminSettings.summary_schedule = s.summary_schedule;
      if (typeof s.ga4_measurement_id === 'string') adminSettings.ga4_measurement_id = s.ga4_measurement_id;
      if (typeof s.ga4_property_id === 'string') adminSettings.ga4_property_id = s.ga4_property_id;
      if (typeof s.gsc_site_url === 'string') adminSettings.gsc_site_url = s.gsc_site_url;
      if (Number.isFinite(Number(s.retention_days_operational_logs))) adminSettings.retention_days_operational_logs = Number(s.retention_days_operational_logs);
      if (Number.isFinite(Number(s.retention_days_contact_messages))) adminSettings.retention_days_contact_messages = Number(s.retention_days_contact_messages);
      if (Number.isFinite(Number(s.session_ttl_hours))) adminSettings.session_ttl_hours = Number(s.session_ttl_hours);
      if (s.ip_logging_mode === 'full' || s.ip_logging_mode === 'masked' || s.ip_logging_mode === 'hashed') adminSettings.ip_logging_mode = s.ip_logging_mode;
      saveAdminSettings();

      // Merge contact inquiry workflow states without losing newer inquiries
      let restoredStatesCount = 0;
      if (parsed.contact_states && typeof parsed.contact_states === 'object') {
        for (const [k, val] of Object.entries(parsed.contact_states)) {
          if (val && typeof val === 'object') {
            contactStates[k] = val as ContactInquiryState;
            restoredStatesCount++;
          }
        }
        saveContactStates();
      }

      recordAuditLog({
        actor: session.username,
        action: 'backup_restored',
        target: rawName,
        req,
        status: 'warning',
        detail: `Restored settings and ${restoredStatesCount} contact states from ${rawName} (pre-restore snapshot: ${preFilename}).`
      });

      return res.json({
        success: true,
        restored_from: rawName,
        pre_restore_backup: preFilename,
        restored_contact_states: restoredStatesCount,
        backups: getBackupsList()
      });
    } catch (err: any) {
      return res.status(500).json({
        success: false,
        error: `Failed to restore backup: ${sanitizeLogSummary(err?.message || 'Parse error')}`
      });
    }
  });

  // 10e. Apply Retention Cleanup Policy (Requires confirmation flag, preserves at least 5 recent backups)
  app.post('/api/admin/retention/run', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    if (req.body?.confirm !== true) {
      return res.status(400).json({
        success: false,
        error: 'Explicit confirmation is required to run retention cleanup.'
      });
    }

    const now = Date.now();
    const opCutoffMs = now - adminSettings.retention_days_operational_logs * 24 * 3600 * 1000;
    const contactCutoffMs = now - adminSettings.retention_days_contact_messages * 24 * 3600 * 1000;

    const pruneJsonlByTimestamp = (filePath: string, cutoffMs: number): number => {
      if (!fs.existsSync(filePath)) return 0;
      const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean);
      const kept: string[] = [];
      let removed = 0;
      for (const line of lines) {
        try {
          const obj = JSON.parse(line);
          const t = Date.parse(obj.timestamp || '');
          if (!Number.isNaN(t) && t < cutoffMs) {
            removed++;
            continue;
          }
        } catch {}
        kept.push(line);
      }
      if (removed > 0) {
        fs.writeFileSync(filePath, kept.join('\n') + (kept.length ? '\n' : ''), { encoding: 'utf8', mode: 0o600 });
      }
      return removed;
    };

    const prunedStats = pruneJsonlByTimestamp(STATS_LOG_FILE, opCutoffMs);
    const prunedErrors = pruneJsonlByTimestamp(ERRORS_LOG_FILE, opCutoffMs);
    const prunedVisitors = pruneJsonlByTimestamp(VISITOR_LOG_FILE, opCutoffMs);
    const prunedActivity = pruneJsonlByTimestamp(ACTIVITY_LOG_FILE, opCutoffMs);
    const prunedContacts = pruneJsonlByTimestamp(CONTACT_LOG_FILE, contactCutoffMs);

    // Prune very old backups beyond operational retention while keeping at least the 5 most recent backups
    let prunedBackups = 0;
    try {
      const allBackups = getBackupsList();
      if (allBackups.length > 5) {
        for (const b of allBackups.slice(5)) {
          const t = Date.parse(b.created_at);
          if (!Number.isNaN(t) && t < opCutoffMs) {
            const p = path.join(backupsDir, b.filename);
            if (fs.existsSync(p)) {
              fs.unlinkSync(p);
              prunedBackups++;
            }
          }
        }
      }
    } catch {}

    recordAuditLog({
      actor: session.username,
      action: 'retention_cleanup_executed',
      target: `${adminSettings.retention_days_operational_logs}d_op_${adminSettings.retention_days_contact_messages}d_contact`,
      req,
      status: 'success',
      detail: `Pruned expired records (stats: ${prunedStats}, activity: ${prunedActivity}, errors: ${prunedErrors}, visitors: ${prunedVisitors}, contacts: ${prunedContacts}, old backups: ${prunedBackups}).`
    });

    return res.json({
      success: true,
      pruned: {
        download_stats: prunedStats,
        activity_events: prunedActivity,
        app_errors: prunedErrors,
        visitor_events: prunedVisitors,
        contact_messages: prunedContacts,
        old_backups: prunedBackups
      }
    });
  });

  return {
    recordAppError,
    recordContactFunnelEvent,
    recordVisitorEvent,
    recordActivityEvent,
    isVisitorBlocked,
    onNewContactInquiryStored
  };
}
