import express, { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
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

function hashClientIp(req: Request): string {
  const rawIp = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown')
    .split(',')[0]
    .trim();
  if (!rawIp || rawIp === 'unknown') return 'ip_unknown';
  // Privacy-preserving salted hash of IP address (never stores raw visitor IP on disk)
  return 'ip_' + crypto.createHash('sha256').update('dd_ip_salt_v1:' + rawIp).digest('hex').slice(0, 12);
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
    // Redact any URLs with query strings or tokens
    .replace(/https?:\/\/[^\s"'<>]+/gi, '[redacted-url]')
    // Redact filesystem paths
    .replace(/\/(?:var|home|app|tmp|usr|etc)\/[^\s"'<>]+/gi, '[redacted-path]')
    // Redact potential tokens/keys
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
      const tmpPath = `${filePath}.tmp.${process.pid}.${Date.now()}`;
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
      // Bound log growth automatically: if file exceeds maxFileSizeBytes, keep newest 60%
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
    updated_at: new Date().toISOString()
  };

  let adminSettings: AdminSettings = {
    ...defaultSettings,
    ...readJsonFileSafe<Partial<AdminSettings>>(SETTINGS_FILE, {})
  };
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

  // ---------------- 4. Admin Users & Bootstrap Setup ----------------

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

    // Emergency password reset via ADMIN_RESET_PASSWORD env var (requires server access)
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
        // Generate or load one-time setup token stored on server disk (mode 0600)
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

  // ---------------- 5. Session Management & Rate Limiting ----------------

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

  // Brute-force login rate limiter
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

  // Middleware for protecting all /api/admin/* endpoints
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

      // Enforce CSRF token on all state-changing methods
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

  // ---------------- 6. Transactional Email Provider (Resend) & Alerting ----------------

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
        // Retry only on 429 or 5xx
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

  // ---------------- 7. Contact State, Funnel Events, Visitor & Error Hooks ----------------

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

  function recordVisitorEvent(req: Request, eventType: VisitorTelemetryEvent['event_type'], extra?: { platform?: string }): void {
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

    const ev: VisitorTelemetryEvent = {
      timestamp: new Date().toISOString(),
      event_type: eventType,
      path: String(req.path || '/').slice(0, 64),
      referrer_host: refHost,
      device_category: detectDeviceCategory(req.headers['user-agent']),
      lang,
      ...(extra?.platform ? { platform: String(extra.platform).slice(0, 24) } : {})
    };
    appendJsonlSafe(VISITOR_LOG_FILE, ev, 5 * 1024 * 1024);
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

    // Track repeated download/API failures in a 10-minute rolling window
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

  // ---------------- 8. Optional Google Service Account JWT Helper (GA4 & Search Console) ----------------

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

  // ---------------- 9. Date Range Filtering Helper ----------------

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

    if (preset === 'today') {
      startMs = todayStart;
      endMs = now.getTime();
    } else if (preset === 'yesterday') {
      startMs = todayStart - dayMs;
      endMs = todayStart - 1;
    } else if (preset === '7d') {
      startMs = todayStart - 6 * dayMs;
    } else if (preset === '28d') {
      startMs = todayStart - 27 * dayMs;
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

  // 2. Public Search-Box Shortcut Check (Never authenticates; only returns { matched: true, redirect: '/admin' })
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

  // 3. Public Telemetry Hook for Contact Form Funnel & First-Party PageView
  const telemetryRateMap = new Map<string, number[]>();
  app.post('/api/public/telemetry', (req: Request, res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    const ipHash = hashClientIp(req);
    const now = Date.now();
    const hits = (telemetryRateMap.get(ipHash) || []).filter(ts => now - ts < 60000);
    if (hits.length >= 30) {
      return res.status(204).end();
    }
    hits.push(now);
    telemetryRateMap.set(ipHash, hits);

    const eventType = String(req.body?.event_type || '').trim();
    const platform = typeof req.body?.platform === 'string' ? req.body.platform.slice(0, 24) : undefined;
    const category = typeof req.body?.category === 'string' ? req.body.category.slice(0, 48) : undefined;
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.slice(0, 80) : undefined;

    if (eventType === 'page_view' || eventType === 'link_submit' || eventType === 'download_click') {
      recordVisitorEvent(req, eventType, { platform });
    } else if (eventType === 'contact_form_opened') {
      recordVisitorEvent(req, 'contact_open');
      recordContactFunnelEvent('form_opened', { category, platform });
    } else if (eventType === 'contact_validation_failed') {
      recordContactFunnelEvent('validation_failed', { category, platform, reason });
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
    // Always perform scrypt verification even if user not found to prevent timing enumeration
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

    // Regenerate session (remove any existing session cookie from request first)
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

    // Revoke other sessions and issue a fresh session for current user
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
    const role: AdminRole = roleRaw === 'admin' ? 'admin' : 'viewer';

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
      return res.status(400).json({ success: false, error: 'You cannot disable your own active owner account.' });
    }

    if (typeof req.body?.disabled === 'boolean') {
      targetUser.disabled = req.body.disabled;
    }
    if (req.body?.role === 'admin' || req.body?.role === 'viewer') {
      if (targetUser.role !== 'owner') {
        targetUser.role = req.body.role;
      }
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

    const curErrors = allErrors.filter(e => inRange(e.timestamp, win.startMs, win.endMs));

    const summarizeDl = (records: DownloadStatRecord[]) => {
      let parseTotal = 0, parseSuccess = 0, parseFailed = 0;
      let dlTotal = 0, dlSuccess = 0, dlFailed = 0, dlAborted = 0;
      let totalLatencyMs = 0;
      const byPlatform: Record<string, { total: number; success: number; failed: number }> = {
        douyin: { total: 0, success: 0, failed: 0 },
        bilibili: { total: 0, success: 0, failed: 0 },
        tiktok: { total: 0, success: 0, failed: 0 },
        xiaohongshu: { total: 0, success: 0, failed: 0 }
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
        avg_duration_ms: records.length > 0 ? Math.round(totalLatencyMs / records.length) : 0,
        by_platform: byPlatform
      };
    };

    const currentDlSummary = summarizeDl(curDownloads);
    const previousDlSummary = summarizeDl(prevDownloads);

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
        if (st.issue_type === 'feedback') feedbackCount++;
      }
      if (inRange(c.timestamp, win.startMs, win.endMs)) {
        periodInquiries++;
      }
    }
    saveContactStates();

    // Daily trend series within window
    const dailyMap = new Map<string, { date: string; page_views: number; parse_requests: number; downloads_success: number; downloads_failed: number }>();
    const daySpan = Math.min(90, Math.max(1, Math.ceil((win.endMs - win.startMs) / (24 * 3600 * 1000))));
    for (let i = daySpan - 1; i >= 0; i--) {
      const dStr = new Date(win.endMs - i * 24 * 3600 * 1000).toISOString().slice(0, 10);
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
      window: {
        preset: win.preset,
        start_date: win.startDateStr,
        end_date: win.endDateStr
      },
      traffic: {
        first_party_page_views: curVisitors.filter(v => v.event_type === 'page_view').length,
        prev_first_party_page_views: prevVisitors.filter(v => v.event_type === 'page_view').length,
        ga4_measurement_id: adminSettings.ga4_measurement_id,
        ga4_data_api_configured: ga4DataApiConfigured,
        unique_visitors_status: ga4DataApiConfigured ? 'available_in_analytics_tab' : 'requires_ga4_data_api'
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

    // Referrer / Channel breakdown from first-party page_view telemetry
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

    // Optional live query to Google Analytics Data API if configured
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
    const periodRecords = allRecords.filter(r => {
      const t = Date.parse(r.timestamp);
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
        avg_latency_ms: 0,
        latency_sum: 0,
        count: 0
      };
    }

    const errorCategories: Record<string, number> = {};
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

    for (const p of platforms) {
      const b = byPlatform[p];
      b.avg_latency_ms = b.count > 0 ? Math.round(b.latency_sum / b.count) : 0;
    }

    const recentFailures = periodRecords
      .filter(r => r.status === 'failed')
      .slice(-50)
      .reverse();

    const recentEvents = periodRecords.slice(-100).reverse();

    return res.json({
      success: true,
      window: { preset: win.preset, start_date: win.startDateStr, end_date: win.endDateStr },
      total_events_in_window: periodRecords.length,
      timeout_count: timeoutCount,
      by_platform: byPlatform,
      error_categories: errorCategories,
      recent_failures: recentFailures,
      recent_events: recentEvents
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
    }).reverse(); // Newest first

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

  // 4b. Update Contact Inquiry State (Mark read/unread, resolved/open, issue_type, notes)
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

  // 4c. Delete Individual Contact Record (GDPR/Privacy Removal with Explicit Confirmation)
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

  // 4c. Export Authenticated Contact Records or Download Stats to CSV
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
    const allErrors = readJsonlTail<AppErrorRecord>(ERRORS_LOG_FILE, 2000).reverse();
    const severityFilter = String(req.query.severity || 'all').toLowerCase();
    const routeFilter = String(req.query.route || 'all').toLowerCase();

    const filtered = allErrors.filter(e => {
      if (severityFilter !== 'all' && e.severity !== severityFilter) return false;
      if (routeFilter !== 'all' && e.route_category !== routeFilter) return false;
      return true;
    });

    const byRoute: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    for (const e of allErrors) {
      byRoute[e.route_category] = (byRoute[e.route_category] || 0) + 1;
      byCategory[e.error_category] = (byCategory[e.error_category] || 0) + 1;
    }

    return res.json({
      success: true,
      total: filtered.length,
      by_route: byRoute,
      by_category: byCategory,
      items: filtered.slice(0, 200)
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

    return res.json({
      success: true,
      application: {
        name: pkg.name || 'douyin-downloader',
        version: pkg.version || '1.0.0',
        node_version: process.version,
        platform_arch: `${process.platform}/${process.arch}`,
        server_started_at: new Date(serverStartTime).toISOString(),
        uptime_seconds: Math.floor((Date.now() - serverStartTime) / 1000)
      },
      resources: {
        process_rss_mb: Math.round(mem.rss / (1024 * 1024)),
        heap_used_mb: Math.round(mem.heapUsed / (1024 * 1024)),
        system_total_ram_mb: Math.round(os.totalmem() / (1024 * 1024)),
        system_free_ram_mb: Math.round(os.freemem() / (1024 * 1024)),
        load_average_1m: Number((os.loadavg()[0] || 0).toFixed(2))
      },
      storage: {
        mode: 'local_persistent_jsonl_and_atomic_json',
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
          contact_messages_bytes: getFileSize(CONTACT_LOG_FILE),
          app_errors_bytes: getFileSize(ERRORS_LOG_FILE),
          audit_log_bytes: getFileSize(AUDIT_LOG_FILE),
          visitor_events_bytes: getFileSize(VISITOR_LOG_FILE)
        },
        backups_count: backups.length,
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
  app.get('/api/admin/seo', requireAdminAuth('viewer'), async (req: Request, res: Response) => {
    const indexPath = path.join(staticDir, 'index.html');
    const sitemapPath = path.join(staticDir, 'sitemap.xml');
    const robotsPath = path.join(staticDir, 'robots.txt');

    let html = '';
    try {
      if (fs.existsSync(indexPath)) html = fs.readFileSync(indexPath, 'utf8');
    } catch {}

    const extractTag = (regex: RegExp) => {
      const m = html.match(regex);
      return m ? m[1].trim() : null;
    };

    const title = extractTag(/<title>([^<]+)<\/title>/i);
    const metaDesc = extractTag(/<meta\s+name=["']description["']\s+content=["']([^"']+)["']/i);
    const canonical = extractTag(/<link\s+rel=["']canonical["']\s+href=["']([^"']+)["']/i);
    const metaRobots = extractTag(/<meta\s+name=["']robots["']\s+content=["']([^"']+)["']/i);
    const ogTitle = extractTag(/<meta\s+property=["']og:title["']\s+content=["']([^"']+)["']/i);
    const ogUrl = extractTag(/<meta\s+property=["']og:url["']\s+content=["']([^"']+)["']/i);
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

    return res.json({
      success: true,
      technical_seo: {
        canonical_url: canonical || 'https://downdouyin.com/',
        canonical_valid: canonical === 'https://downdouyin.com/',
        https_enforced_in_canonical: Boolean(canonical && canonical.startsWith('https://downdouyin.com')),
        title,
        title_length: title ? title.length : 0,
        meta_description: metaDesc,
        meta_description_length: metaDesc ? metaDesc.length : 0,
        meta_robots: metaRobots,
        og_title: ogTitle,
        og_url: ogUrl,
        structured_data_json_ld: hasJsonLd,
        sitemap_endpoint: 'https://downdouyin.com/sitemap.xml',
        sitemap_file_present: fs.existsSync(sitemapPath),
        robots_endpoint: 'https://downdouyin.com/robots.txt',
        robots_file_present: fs.existsSync(robotsPath),
        robots_content: fs.existsSync(robotsPath) ? fs.readFileSync(robotsPath, 'utf8') : ''
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
      detail: result.sent ? `Test email sent (${result.providerId})` : `Test email failed: ${result.error}`
    });

    if (!result.sent) {
      return res.status(400).json({
        success: false,
        error: result.error || 'Failed to send test email.'
      });
    }
    return res.json({ success: true, provider_id: result.providerId });
  });

  // 9. Security & Audit Log (/api/admin/audit)
  app.get('/api/admin/audit', requireAdminAuth('viewer'), (req: Request, res: Response) => {
    const logs = readJsonlTail<AuditLogRecord>(AUDIT_LOG_FILE, 1000).reverse();
    const activeSessionsList = Array.from(activeSessions.values()).map(s => ({
      username: s.username,
      role: s.role,
      created_at: new Date(s.created_at).toISOString(),
      last_active_at: new Date(s.last_active_at).toISOString(),
      expires_at: new Date(s.expires_at).toISOString(),
      user_agent_summary: s.user_agent_summary,
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
      audit_logs: logs.slice(0, 250)
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

  // 10b. Create Snapshot Backup
  app.post('/api/admin/backups/create', requireAdminAuth('admin'), (req: Request, res: Response) => {
    const session: AdminSession = (req as any).adminSession;
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `backup-${stamp}.json`;
    const dest = path.join(backupsDir, filename);

    const payload = {
      created_at: new Date().toISOString(),
      created_by: session.username,
      settings: adminSettings,
      contact_inquiries: readJsonlTail<RawContactRecord>(CONTACT_LOG_FILE, 5000),
      contact_states: contactStates,
      download_stats_summary: deps.getDownloadStats().summary
    };

    writeJsonFileAtomic(dest, payload);
    const st = fs.statSync(dest);

    recordAuditLog({
      actor: session.username,
      action: 'backup_created',
      target: filename,
      req,
      status: 'success',
      detail: `Created operational & contact snapshot backup (${st.size} bytes).`
    });

    return res.json({
      success: true,
      backup: {
        backup_id: filename.replace(/\.json$/, ''),
        filename,
        created_at: st.mtime.toISOString(),
        size_bytes: st.size,
        created_by: session.username
      }
    });
  });

  // 10c. Apply Retention Cleanup Policy (Requires confirmation flag)
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

    recordAuditLog({
      actor: session.username,
      action: 'retention_cleanup_executed',
      target: `${adminSettings.retention_days_operational_logs}d_policy`,
      req,
      status: 'success',
      detail: `Pruned expired operational logs (stats: ${prunedStats}, errors: ${prunedErrors}, visitors: ${prunedVisitors}).`
    });

    return res.json({
      success: true,
      pruned: {
        download_stats: prunedStats,
        app_errors: prunedErrors,
        visitor_events: prunedVisitors
      }
    });
  });

  return {
    recordAppError,
    recordContactFunnelEvent,
    recordVisitorEvent,
    onNewContactInquiryStored
  };
}
