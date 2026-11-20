import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type Request, type Response, type NextFunction } from 'express';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 3000);
const MEMORY_VAULT_FRONTEND = path.resolve(__dirname, 'MEMORY-VAULT', 'frontend');

// ============================================================================
// Password Hashing Helpers (Node scrypt, timing-safe)
// ============================================================================
function hashPassword(plain: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(plain: string, stored: string): boolean {
  const parts = stored.split(':');
  if (parts.length !== 2) return false;
  const [salt, keyHex] = parts;
  const derived = crypto.scryptSync(plain, salt, 64);
  const keyBuf = Buffer.from(keyHex, 'hex');
  if (derived.length !== keyBuf.length) return false;
  return crypto.timingSafeEqual(derived, keyBuf);
}

// ============================================================================
// In-Memory Preview Data Store (Exact Mirror of supabase_schema.sql Seed Data)
// ============================================================================
interface UserRow {
  id: number;
  user_handle: string;
  full_name: string;
  email: string;
  password_hash: string;
  last_check_in: string;
  escalation_stage: number;
  inactivity_cycle_id: string;
  created_at: string;
  updated_at: string;
}

interface AdminRow {
  id: number;
  full_name: string;
  email: string;
  password_hash: string;
  role: string;
  created_at: string;
}

interface AssetRow {
  id: number;
  user_id: number;
  asset_name: string;
  platform: string;
  category: string;
  account_identifier: string;
  notes: string;
  created_at: string;
  updated_at: string;
}

interface ContactRow {
  id: number;
  user_id: number;
  name: string;
  email: string;
  phone: string;
  relationship: string;
  invitation_token: string;
  invitation_status: 'pending' | 'accepted' | 'declined';
  responded_at: string | null;
  created_at: string;
  updated_at: string;
}

interface WishRow {
  id: number;
  user_id: number;
  asset_id: number;
  assigned_contact_id: number | null;
  action_type: string;
  custom_instructions: string;
  created_at: string;
  updated_at: string;
}

interface MemoryRow {
  id: number;
  user_id: number;
  trusted_contact_id: number | null;
  custom_recipient: string;
  title: string;
  message_body: string;
  release_condition: string;
  created_at: string;
  updated_at: string;
}

interface LegacyPlanRow {
  id: number;
  user_id: number;
  first_reminder_days: number;
  second_reminder_days: number;
  final_reminder_days: number;
  trusted_alert_days: number;
  general_guidance: string;
}

interface LegacyRequestRow {
  id: number;
  request_code: string;
  user_id: number;
  trusted_contact_id: number;
  requester_email: string;
  reason: string;
  verification_note: string;
  status: 'pending' | 'approved' | 'rejected';
  admin_remarks: string;
  reviewed_by: number | null;
  reviewed_at: string | null;
  created_at: string;
  updated_at: string;
}

interface NotificationLogRow {
  id: number;
  user_id: number | null;
  recipient_email: string;
  recipient_role: string;
  notification_type: string;
  cycle_id: string;
  subject: string;
  body: string;
  delivery_status: string;
  created_at: string;
}

interface AdminAuditRow {
  id: number;
  admin_id: number;
  legacy_request_id: number | null;
  action: string;
  remarks: string;
  created_at: string;
}

const daysAgoIso = (days: number) => new Date(Date.now() - days * 86400 * 1000).toISOString();
const nowIso = () => new Date().toISOString();

const db = {
  seq: {
    users: 2,
    assets: 6,
    contacts: 4,
    wishes: 6,
    memories: 4,
    plans: 2,
    requests: 2,
    notifications: 3,
    audits: 1,
  },
  users: [
    {
      id: 1,
      user_handle: 'aarav_mehta',
      full_name: 'Aarav Mehta',
      email: 'demo@memoryvault.com',
      password_hash: hashPassword('Demo@1234'),
      last_check_in: daysAgoIso(4),
      escalation_stage: 0,
      inactivity_cycle_id: 'cycle_demo_2026',
      created_at: daysAgoIso(40),
      updated_at: daysAgoIso(4),
    },
  ] as UserRow[],
  admins: [
    {
      id: 1,
      full_name: 'Dr. Kavita Rao',
      email: 'admin@memoryvault.com',
      password_hash: hashPassword('Admin@1234'),
      role: 'chief_verifier',
      created_at: daysAgoIso(90),
    },
  ] as AdminRow[],
  plans: [
    {
      id: 1,
      user_id: 1,
      first_reminder_days: 30,
      second_reminder_days: 35,
      final_reminder_days: 40,
      trusted_alert_days: 45,
      general_guidance:
        'Please handle all accounts with care and follow official provider legacy processes. Never attempt unauthorized sign-ins; preserve family photographs first.',
    },
  ] as LegacyPlanRow[],
  contacts: [
    {
      id: 1,
      user_id: 1,
      name: 'Meera Mehta',
      email: 'meera.mehta@example.com',
      phone: '+91 98201 44120',
      relationship: 'Sister',
      invitation_token: 'mv_inv_meera_8f3a91c2d4b0e711',
      invitation_status: 'accepted',
      responded_at: daysAgoIso(18),
      created_at: daysAgoIso(25),
      updated_at: daysAgoIso(18),
    },
    {
      id: 2,
      user_id: 1,
      name: 'Rohan Kulkarni',
      email: 'rohan.kulkarni@example.com',
      phone: '+91 98450 77312',
      relationship: 'Close Friend & Executor',
      invitation_token: 'mv_inv_rohan_5b2c19a8e6f3d420',
      invitation_status: 'accepted',
      responded_at: daysAgoIso(12),
      created_at: daysAgoIso(20),
      updated_at: daysAgoIso(12),
    },
    {
      id: 3,
      user_id: 1,
      name: 'Ananya Deshmukh',
      email: 'ananya.d@example.com',
      phone: '+91 97654 21890',
      relationship: 'Cousin',
      invitation_token: 'mv_inv_ananya_1c9e44b7a2d5f803',
      invitation_status: 'pending',
      responded_at: null,
      created_at: daysAgoIso(6),
      updated_at: daysAgoIso(6),
    },
  ] as ContactRow[],
  assets: [
    {
      id: 1,
      user_id: 1,
      asset_name: 'Family Photo Archive',
      platform: 'Google Photos',
      category: 'Cloud Photos',
      account_identifier: 'aarav.mehta.archive@gmail.com',
      notes: 'Contains albums from 2014–2026 including Ladakh trip, graduation, and family gatherings.',
      created_at: daysAgoIso(30),
      updated_at: daysAgoIso(10),
    },
    {
      id: 2,
      user_id: 1,
      asset_name: 'Personal Instagram Journal',
      platform: 'Instagram',
      category: 'Social Media',
      account_identifier: '@aarav.frames',
      notes: 'Film photography visual diary and travel captions.',
      created_at: daysAgoIso(28),
      updated_at: daysAgoIso(10),
    },
    {
      id: 3,
      user_id: 1,
      asset_name: 'Primary Email Account',
      platform: 'Gmail',
      category: 'Email',
      account_identifier: 'aarav.mehta.archive@gmail.com',
      notes: 'Linked to academic certificates, tax receipts, and Google Inactive Account Manager.',
      created_at: daysAgoIso(25),
      updated_at: daysAgoIso(10),
    },
    {
      id: 4,
      user_id: 1,
      asset_name: 'Creative Writing & Research Drive',
      platform: 'Google Drive',
      category: 'Cloud Storage',
      account_identifier: 'aarav.mehta.archive@gmail.com',
      notes: 'Folder titled "Essays & Drafts" holds unpublished short stories and project archives.',
      created_at: daysAgoIso(22),
      updated_at: daysAgoIso(10),
    },
    {
      id: 5,
      user_id: 1,
      asset_name: 'Streaming & Cloud Subscriptions',
      platform: 'Spotify & Adobe Creative Cloud',
      category: 'Subscriptions',
      account_identifier: 'aarav.mehta.archive@gmail.com',
      notes: 'Monthly recurring billing linked to primary debit card; cancel via official support.',
      created_at: daysAgoIso(20),
      updated_at: daysAgoIso(10),
    },
  ] as AssetRow[],
  wishes: [
    {
      id: 1,
      user_id: 1,
      asset_id: 1,
      assigned_contact_id: 1,
      action_type: 'preserve_memories',
      custom_instructions:
        'Export the "Family Years" and "Himalayan Trails" albums via Google Takeout through official next-of-kin channels and share copies with our parents.',
      created_at: daysAgoIso(20),
      updated_at: daysAgoIso(10),
    },
    {
      id: 2,
      user_id: 1,
      asset_id: 2,
      assigned_contact_id: 1,
      action_type: 'request_memorialization',
      custom_instructions:
        'Submit an official Instagram memorialization request so the photography grid remains viewable to friends without new posts.',
      created_at: daysAgoIso(20),
      updated_at: daysAgoIso(10),
    },
    {
      id: 3,
      user_id: 1,
      asset_id: 3,
      assigned_contact_id: 2,
      action_type: 'share_information',
      custom_instructions:
        'Coordinate with Google Inactive Account Manager to download tax and academic records, then close the inbox respectfully.',
      created_at: daysAgoIso(20),
      updated_at: daysAgoIso(10),
    },
    {
      id: 4,
      user_id: 1,
      asset_id: 4,
      assigned_contact_id: 2,
      action_type: 'preserve_account',
      custom_instructions:
        'Archive the "Essays & Drafts" folder to an external drive and keep the literary notebooks safe for family reading.',
      created_at: daysAgoIso(20),
      updated_at: daysAgoIso(10),
    },
    {
      id: 5,
      user_id: 1,
      asset_id: 5,
      assigned_contact_id: 2,
      action_type: 'request_deletion',
      custom_instructions:
        'Contact Spotify and Adobe customer support with official documentation to cancel recurring subscriptions and close billing profiles.',
      created_at: daysAgoIso(20),
      updated_at: daysAgoIso(10),
    },
  ] as WishRow[],
  memories: [
    {
      id: 1,
      user_id: 1,
      trusted_contact_id: 1,
      custom_recipient: '',
      title: 'For Meera — Keep the Cameras Rolling',
      message_body:
        'Dearest Meera,\n\nIf you are reading this letter, I hope you are sitting somewhere quiet with a warm cup of filter coffee. Every photograph in our shared archive carries a story only the two of us remember—from rainy monsoon evenings on the balcony to our long bus ride through Himachal.\n\nPlease keep my old 35mm camera on your bookshelf, and whenever life feels hurried, flip through the family albums and remember how deeply loved you have always been.\n\nWith all my warmth,\nAarav',
      release_condition: 'Upon verified admin approval',
      created_at: daysAgoIso(15),
      updated_at: daysAgoIso(15),
    },
    {
      id: 2,
      user_id: 1,
      trusted_contact_id: 2,
      custom_recipient: '',
      title: 'To Rohan — Notes on My Notebooks & Playlists',
      message_body:
        'Hey Rohan,\n\nThank you for being the steadying voice in every chapter since our first semester. I have left instructions for the Creative Writing Drive so you can archive my unfinished essays and keep the acoustic road-trip playlist alive.\n\nTake care of yourself, keep building things that matter, and never lose your curiosity.\n\nAlways grateful,\nAarav',
      release_condition: 'Upon verified admin approval',
      created_at: daysAgoIso(14),
      updated_at: daysAgoIso(14),
    },
    {
      id: 3,
      user_id: 1,
      trusted_contact_id: 1,
      custom_recipient: 'Mom & Dad',
      title: 'A Quiet Letter for Mom and Dad',
      message_body:
        'Dear Mom and Dad,\n\nEverything gentle and resilient in me came directly from watching the two of you. Thank you for giving me roots deep enough to weather storms and wings wide enough to explore the world.\n\nMeera has the list of family photo albums I curated especially for you. Please know my life was filled with gratitude because of our home.\n\nLove always,\nAarav',
      release_condition: 'Upon verified admin approval',
      created_at: daysAgoIso(12),
      updated_at: daysAgoIso(12),
    },
  ] as MemoryRow[],
  requests: [
    {
      id: 1,
      request_code: 'REQ-2026-8412',
      user_id: 1,
      trusted_contact_id: 1,
      requester_email: 'meera.mehta@example.com',
      reason: 'Family stewardship & photo archive preservation',
      verification_note:
        'Sister listed as primary trusted contact. Submitting formal family verification reference #FAM-2026-09 for administrative review.',
      status: 'pending',
      admin_remarks: '',
      reviewed_by: null,
      reviewed_at: null,
      created_at: daysAgoIso(1),
      updated_at: daysAgoIso(1),
    },
  ] as LegacyRequestRow[],
  notifications: [
    {
      id: 1,
      user_id: 1,
      recipient_email: 'meera.mehta@example.com',
      recipient_role: 'trusted_contact',
      notification_type: 'contact_invitation',
      cycle_id: 'cycle_demo_2026',
      subject: 'You were named a Trusted Contact on Memory Vault',
      body: 'Aarav Mehta has invited you as a Trusted Contact on Memory Vault. Accepting does not automatically grant access to private vault data.',
      delivery_status: 'logged_demo_fallback',
      created_at: daysAgoIso(25),
    },
    {
      id: 2,
      user_id: 1,
      recipient_email: 'demo@memoryvault.com',
      recipient_role: 'user',
      notification_type: 'check_in_reset',
      cycle_id: 'cycle_demo_2026',
      subject: 'Memory Vault Check-In Confirmed',
      body: 'Your activity timer was confirmed active. Next inactivity reminder is scheduled in 30 days.',
      delivery_status: 'logged_demo_fallback',
      created_at: daysAgoIso(4),
    },
  ] as NotificationLogRow[],
  audits: [] as AdminAuditRow[],
};

// ============================================================================
// Secure Cookie Sessions & CSRF Middleware
// ============================================================================
interface SessionData {
  id: string;
  userId: number | null;
  adminId: number | null;
  csrfToken: string;
}

const sessions = new Map<string, SessionData>();

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > -1) {
      out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return out;
}

function attachSession(req: Request, res: Response, next: NextFunction) {
  const cookies = parseCookies(req.headers.cookie);
  let sid = cookies['MV_SESSION'];
  let sess = sid ? sessions.get(sid) : undefined;

  if (!sess) {
    sid = crypto.randomBytes(24).toString('hex');
    sess = {
      id: sid,
      userId: null,
      adminId: null,
      csrfToken: crypto.randomBytes(32).toString('hex'),
    };
    sessions.set(sid, sess);
    res.setHeader(
      'Set-Cookie',
      `MV_SESSION=${sid}; Path=/; HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=21600`
    );
  }

  (req as Request & { mvSession: SessionData }).mvSession = sess;
  next();
}

function getSession(req: Request): SessionData {
  return (req as Request & { mvSession: SessionData }).mvSession;
}

function verifyCsrf(req: Request, res: Response): boolean {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return true;
  const sess = getSession(req);
  const headerToken = String(req.headers['x-csrf-token'] || '');
  if (!headerToken || !sess.csrfToken || headerToken.length !== sess.csrfToken.length) {
    res.status(403).json({ success: false, error: 'Invalid or missing CSRF security token.' });
    return false;
  }
  if (!crypto.timingSafeEqual(Buffer.from(headerToken), Buffer.from(sess.csrfToken))) {
    res.status(403).json({ success: false, error: 'Invalid CSRF security token.' });
    return false;
  }
  return true;
}

function requireUser(req: Request, res: Response): UserRow | null {
  const sess = getSession(req);
  if (!sess.userId) {
    res.status(401).json({ success: false, error: 'Authentication required. Please sign in.' });
    return null;
  }
  const user = db.users.find((u) => u.id === sess.userId);
  if (!user) {
    sess.userId = null;
    res.status(401).json({ success: false, error: 'Session expired. Please sign in again.' });
    return null;
  }
  return user;
}

function requireAdmin(req: Request, res: Response): AdminRow | null {
  const sess = getSession(req);
  if (!sess.adminId) {
    res.status(401).json({ success: false, error: 'Administrator authentication required.' });
    return null;
  }
  const admin = db.admins.find((a) => a.id === sess.adminId);
  if (!admin) {
    sess.adminId = null;
    res.status(401).json({ success: false, error: 'Administrator session expired.' });
    return null;
  }
  return admin;
}

// ============================================================================
// Notification & Inactivity Engine (Exact Mirror of check_inactivity.php)
// ============================================================================
function logNotification(
  userId: number | null,
  recipientEmail: string,
  recipientRole: string,
  notificationType: string,
  subject: string,
  body: string,
  cycleId = '',
  preventDuplicate = false
): boolean {
  const normalizedEmail = recipientEmail.trim().toLowerCase();
  if (preventDuplicate && userId !== null && cycleId) {
    const exists = db.notifications.some(
      (n) =>
        n.user_id === userId &&
        n.cycle_id === cycleId &&
        n.notification_type === notificationType &&
        n.recipient_email.toLowerCase() === normalizedEmail
    );
    if (exists) return false;
  }

  db.notifications.unshift({
    id: db.seq.notifications++,
    user_id: userId,
    recipient_email: normalizedEmail,
    recipient_role: recipientRole,
    notification_type: notificationType,
    cycle_id: cycleId,
    subject,
    body,
    delivery_status: 'logged_demo_fallback',
    created_at: nowIso(),
  });
  return true;
}

function daysInactiveFor(user: UserRow): number {
  const diffMs = Date.now() - new Date(user.last_check_in).getTime();
  return Math.max(0, Math.floor(diffMs / 86400000));
}

function evaluateInactivityForUser(user: UserRow) {
  const plan = db.plans.find((p) => p.user_id === user.id) || {
    first_reminder_days: 30,
    second_reminder_days: 35,
    final_reminder_days: 40,
    trusted_alert_days: 45,
  };
  const days = daysInactiveFor(user);
  const triggered: Array<{ stage: number; type: string; recipient: string; summary: string }> = [];
  let newStage = user.escalation_stage;

  if (days >= plan.first_reminder_days && user.escalation_stage < 1) {
    if (
      logNotification(
        user.id,
        user.email,
        'user',
        'day_30_reminder',
        'Memory Vault — First Activity Check-In Reminder (Day 30)',
        `Hello ${user.full_name}, it has been ${days} days since your last check-in. Please sign in or click Check In Now.`,
        user.inactivity_cycle_id,
        true
      )
    ) {
      triggered.push({
        stage: 1,
        type: 'day_30_reminder',
        recipient: user.email,
        summary: 'Day 30 first reminder sent to vault owner.',
      });
    }
    newStage = Math.max(newStage, 1);
  }

  if (days >= plan.second_reminder_days && user.escalation_stage < 2) {
    if (
      logNotification(
        user.id,
        user.email,
        'user',
        'day_35_reminder',
        'Memory Vault — Second Activity Check-In Reminder (Day 35)',
        `Hello ${user.full_name}, this is your second reminder (${days} days inactive). Please confirm activity on Memory Vault.`,
        user.inactivity_cycle_id,
        true
      )
    ) {
      triggered.push({
        stage: 2,
        type: 'day_35_reminder',
        recipient: user.email,
        summary: 'Day 35 second reminder sent to vault owner.',
      });
    }
    newStage = Math.max(newStage, 2);
  }

  if (days >= plan.final_reminder_days && user.escalation_stage < 3) {
    if (
      logNotification(
        user.id,
        user.email,
        'user',
        'day_40_reminder',
        'Memory Vault — Final Activity Check-In Reminder (Day 40)',
        `Hello ${user.full_name}, final reminder: ${days} days inactive. At Day ${plan.trusted_alert_days}, trusted contacts will be asked to check on you.`,
        user.inactivity_cycle_id,
        true
      )
    ) {
      triggered.push({
        stage: 3,
        type: 'day_40_reminder',
        recipient: user.email,
        summary: 'Day 40 final reminder sent to vault owner.',
      });
    }
    newStage = Math.max(newStage, 3);
  }

  if (days >= plan.trusted_alert_days && user.escalation_stage < 4) {
    const activeContacts = db.contacts.filter(
      (c) => c.user_id === user.id && c.invitation_status !== 'declined'
    );
    for (const contact of activeContacts) {
      if (
        logNotification(
          user.id,
          contact.email,
          'trusted_contact',
          'day_45_trusted_alert',
          `Memory Vault Wellness Check — Please Check on ${user.full_name}`,
          `Hello ${contact.name}, ${user.full_name} has not checked in for ${days} days. Inactivity is NOT proof of death and no vault contents have been released.`,
          user.inactivity_cycle_id,
          true
        )
      ) {
        triggered.push({
          stage: 4,
          type: 'day_45_trusted_alert',
          recipient: contact.email,
          summary: `Day 45 wellness alert sent to trusted contact ${contact.name} (${contact.email}).`,
        });
      }
    }
    newStage = Math.max(newStage, 4);
  }

  user.escalation_stage = newStage;
  user.updated_at = nowIso();

  return { evaluated: true, user_id: user.id, days_inactive: days, stage: newStage, triggered };
}

function buildDashboardData(user: UserRow) {
  const plan = db.plans.find((p) => p.user_id === user.id) || {
    first_reminder_days: 30,
    second_reminder_days: 35,
    final_reminder_days: 40,
    trusted_alert_days: 45,
    general_guidance: '',
  };
  const userAssets = db.assets.filter((a) => a.user_id === user.id);
  const userWishes = db.wishes.filter((w) => w.user_id === user.id);
  const userContacts = db.contacts.filter((c) => c.user_id === user.id);
  const acceptedContacts = userContacts.filter((c) => c.invitation_status === 'accepted').length;
  const userMemories = db.memories.filter((m) => m.user_id === user.id);

  const scoreAssets = userAssets.length > 0 ? 25 : 0;
  const scoreWishes =
    userAssets.length > 0 && userWishes.length > 0
      ? Math.round(25 * Math.min(1, userWishes.length / userAssets.length))
      : 0;
  const scoreContacts = acceptedContacts > 0 ? 25 : userContacts.length > 0 ? 15 : 0;
  const scoreMemories = userMemories.length > 0 ? 25 : 0;
  const completionPct = Math.min(100, scoreAssets + scoreWishes + scoreContacts + scoreMemories);

  const days = daysInactiveFor(user);
  const stage = user.escalation_stage;
  const statusMap: Record<number, { label: string; tone: string }> = {
    0: { label: 'Active', tone: 'success' },
    1: { label: 'Day 30 — First Reminder Sent', tone: 'warning' },
    2: { label: 'Day 35 — Second Reminder Sent', tone: 'warning' },
    3: { label: 'Day 40 — Final Reminder Sent', tone: 'warning' },
    4: { label: 'Day 45+ — Trusted Contacts Notified', tone: 'error' },
  };
  const st = statusMap[stage] || statusMap[0];

  const offsetDays =
    stage === 1
      ? plan.second_reminder_days
      : stage === 2
      ? plan.final_reminder_days
      : stage >= 3
      ? plan.trusted_alert_days
      : plan.first_reminder_days;
  const nextReminder = new Date(new Date(user.last_check_in).getTime() + offsetDays * 86400000).toISOString();

  return {
    user: {
      id: user.id,
      user_handle: user.user_handle,
      full_name: user.full_name,
      email: user.email,
      last_check_in: user.last_check_in,
      escalation_stage: stage,
    },
    metrics: {
      total_assets: userAssets.length,
      total_wishes: userWishes.length,
      total_contacts: userContacts.length,
      accepted_contacts: acceptedContacts,
      total_memories: userMemories.length,
      completion_percent: completionPct,
      days_inactive: days,
      last_check_in: user.last_check_in,
      next_reminder_date: nextReminder,
      status_label: st.label,
      status_tone: st.tone,
      escalation_stage: stage,
    },
    plan,
    recent_notifications: db.notifications.filter((n) => n.user_id === user.id).slice(0, 15),
  };
}

// ============================================================================
// Express Server Setup
// ============================================================================
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(attachSession);

const apiRouter = express.Router();

// 1. auth.php / auth
apiRouter.all(['/auth.php', '/auth'], (req, res) => {
  const action = String(req.query.action || '');
  const sess = getSession(req);

  if (req.method === 'GET' && (action === 'me' || action === '')) {
    const user = sess.userId ? db.users.find((u) => u.id === sess.userId) || null : null;
    const admin = sess.adminId ? db.admins.find((a) => a.id === sess.adminId) || null : null;
    return res.json({
      success: true,
      authenticated: Boolean(user),
      admin_authenticated: Boolean(admin),
      user: user
        ? {
            id: user.id,
            user_handle: user.user_handle,
            full_name: user.full_name,
            email: user.email,
            last_check_in: user.last_check_in,
            escalation_stage: user.escalation_stage,
            created_at: user.created_at,
          }
        : null,
      admin: admin
        ? { id: admin.id, full_name: admin.full_name, email: admin.email, role: admin.role }
        : null,
      csrf_token: sess.csrfToken,
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method not allowed.' });
  }
  if (!verifyCsrf(req, res)) return;

  const body = req.body || {};

  if (action === 'register') {
    const user_handle = String(body.user_handle || '').trim();
    const full_name = String(body.full_name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');

    if (!/^[a-zA-Z0-9._-]{3,40}$/.test(user_handle)) {
      return res.status(422).json({ success: false, error: 'User ID must be 3–40 valid characters.' });
    }
    if (full_name.length < 2) {
      return res.status(422).json({ success: false, error: 'Please enter your full name.' });
    }
    if (!email.includes('@')) {
      return res.status(422).json({ success: false, error: 'Please enter a valid email address.' });
    }
    if (password.length < 8) {
      return res.status(422).json({ success: false, error: 'Password must be at least 8 characters long.' });
    }
    if (
      db.users.some(
        (u) => u.email.toLowerCase() === email || u.user_handle.toLowerCase() === user_handle.toLowerCase()
      )
    ) {
      return res.status(409).json({ success: false, error: 'An account with that email or User ID already exists.' });
    }

    const newUser: UserRow = {
      id: db.seq.users++,
      user_handle,
      full_name,
      email,
      password_hash: hashPassword(password),
      last_check_in: nowIso(),
      escalation_stage: 0,
      inactivity_cycle_id: 'cycle_' + crypto.randomBytes(6).toString('hex'),
      created_at: nowIso(),
      updated_at: nowIso(),
    };
    db.users.push(newUser);
    db.plans.push({
      id: db.seq.plans++,
      user_id: newUser.id,
      first_reminder_days: 30,
      second_reminder_days: 35,
      final_reminder_days: 40,
      trusted_alert_days: 45,
      general_guidance: '',
    });

    sess.userId = newUser.id;
    sess.csrfToken = crypto.randomBytes(32).toString('hex');
    return res.status(201).json({
      success: true,
      message: 'Your Memory Vault account has been created.',
      user: {
        id: newUser.id,
        user_handle: newUser.user_handle,
        full_name: newUser.full_name,
        email: newUser.email,
        last_check_in: newUser.last_check_in,
        escalation_stage: 0,
      },
      csrf_token: sess.csrfToken,
    });
  }

  if (action === 'login') {
    const identifier = String(body.identifier || '').trim().toLowerCase();
    const password = String(body.password || '');
    const user = db.users.find(
      (u) => u.email.toLowerCase() === identifier || u.user_handle.toLowerCase() === identifier
    );
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ success: false, error: 'Invalid email/User ID or password.' });
    }
    user.last_check_in = nowIso();
    user.escalation_stage = 0;
    user.inactivity_cycle_id = 'cycle_' + crypto.randomBytes(6).toString('hex');
    user.updated_at = nowIso();

    sess.userId = user.id;
    sess.csrfToken = crypto.randomBytes(32).toString('hex');
    return res.json({
      success: true,
      message: 'Welcome back. Your activity check-in timer has been refreshed.',
      user: {
        id: user.id,
        user_handle: user.user_handle,
        full_name: user.full_name,
        email: user.email,
        last_check_in: user.last_check_in,
        escalation_stage: 0,
      },
      csrf_token: sess.csrfToken,
    });
  }

  if (action === 'logout') {
    sess.userId = null;
    sess.csrfToken = crypto.randomBytes(32).toString('hex');
    return res.json({ success: true, message: 'Signed out safely.', csrf_token: sess.csrfToken });
  }

  if (action === 'admin_login') {
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const admin = db.admins.find((a) => a.email.toLowerCase() === email);
    if (!admin || !verifyPassword(password, admin.password_hash)) {
      return res.status(401).json({ success: false, error: 'Invalid administrator credentials.' });
    }
    sess.adminId = admin.id;
    sess.csrfToken = crypto.randomBytes(32).toString('hex');
    return res.json({
      success: true,
      message: 'Administrator session started.',
      admin: { id: admin.id, full_name: admin.full_name, email: admin.email, role: admin.role },
      csrf_token: sess.csrfToken,
    });
  }

  if (action === 'admin_logout') {
    sess.adminId = null;
    sess.csrfToken = crypto.randomBytes(32).toString('hex');
    return res.json({ success: true, message: 'Administrator signed out.', csrf_token: sess.csrfToken });
  }

  return res.status(400).json({ success: false, error: 'Unknown authentication action.' });
});

// 2. dashboard.php / dashboard
apiRouter.all(['/dashboard.php', '/dashboard'], (req, res) => {
  const user = requireUser(req, res);
  if (!user) return;
  const action = String(req.query.action || '');

  if (req.method === 'GET') {
    return res.json({ success: true, data: buildDashboardData(user) });
  }
  if (req.method === 'POST') {
    if (!verifyCsrf(req, res)) return;
    if (action === 'checkin') {
      user.last_check_in = nowIso();
      user.escalation_stage = 0;
      user.inactivity_cycle_id = 'cycle_' + crypto.randomBytes(6).toString('hex');
      user.updated_at = nowIso();
      logNotification(
        user.id,
        user.email,
        'user',
        'check_in_reset',
        'Memory Vault — Manual Check-In Confirmed',
        `Hello ${user.full_name}, your manual check-in succeeded and reset your inactivity timer to Day 0.`,
        user.inactivity_cycle_id,
        false
      );
      return res.json({
        success: true,
        message: 'Check-in confirmed. Your inactivity timer is reset to Active (Day 0).',
        data: buildDashboardData(user),
      });
    }
    if (action === 'simulate_inactivity') {
      const days = Number(req.body?.days || 0);
      if (![0, 30, 35, 40, 45, 46].includes(days)) {
        return res.status(422).json({ success: false, error: 'Invalid simulation days value.' });
      }
      if (days === 0) {
        user.last_check_in = nowIso();
        user.escalation_stage = 0;
        user.inactivity_cycle_id = 'cycle_' + crypto.randomBytes(6).toString('hex');
        return res.json({
          success: true,
          message: 'Demo simulation reset to 0 days (Active).',
          triggered: [],
          data: buildDashboardData(user),
        });
      }
      const targetStage = days >= 45 ? 4 : days >= 40 ? 3 : days >= 35 ? 2 : 1;
      if (targetStage <= user.escalation_stage) {
        user.escalation_stage = 0;
        user.inactivity_cycle_id = 'sim_' + crypto.randomBytes(6).toString('hex');
      }
      user.last_check_in = daysAgoIso(days);
      const evalRes = evaluateInactivityForUser(user);
      return res.json({
        success: true,
        message: `Simulated ${days} days of inactivity and executed check_inactivity.php.`,
        triggered: evalRes.triggered,
        data: buildDashboardData(user),
      });
    }
  }
  return res.status(405).json({ success: false, error: 'Method not allowed.' });
});

// 3. assets.php / assets
apiRouter.all(['/assets.php', '/assets'], (req, res) => {
  const user = requireUser(req, res);
  if (!user) return;

  if (req.method === 'GET') {
    const assets = db.assets
      .filter((a) => a.user_id === user.id)
      .sort((a, b) => b.id - a.id)
      .map((a) => {
        const w = db.wishes.find((x) => x.asset_id === a.id && x.user_id === user.id);
        return { ...a, wish_id: w?.id || null, wish_action_type: w?.action_type || null };
      });
    return res.json({ success: true, assets });
  }

  if (!verifyCsrf(req, res)) return;
  const body = req.body || {};

  if (body.password !== undefined || body.account_password !== undefined) {
    return res.status(422).json({
      success: false,
      error: 'Security Policy: Memory Vault never collects or stores third-party account passwords.',
    });
  }

  if (req.method === 'POST') {
    const asset_name = String(body.asset_name || '').trim();
    const platform = String(body.platform || '').trim();
    const category = String(body.category || '').trim();
    const account_identifier = String(body.account_identifier || '').trim();
    const notes = String(body.notes || '').trim();
    if (!asset_name || !platform || !category || !account_identifier) {
      return res.status(422).json({ success: false, error: 'All required asset fields must be completed.' });
    }
    const created: AssetRow = {
      id: db.seq.assets++,
      user_id: user.id,
      asset_name,
      platform,
      category,
      account_identifier,
      notes,
      created_at: nowIso(),
      updated_at: nowIso(),
    };
    db.assets.push(created);
    return res.status(201).json({ success: true, message: 'Digital asset saved to your vault.', asset: created });
  }

  if (req.method === 'PUT') {
    const id = Number(body.id || 0);
    const asset = db.assets.find((a) => a.id === id && a.user_id === user.id);
    if (!asset) return res.status(404).json({ success: false, error: 'Digital asset not found.' });
    asset.asset_name = String(body.asset_name || '').trim();
    asset.platform = String(body.platform || '').trim();
    asset.category = String(body.category || '').trim();
    asset.account_identifier = String(body.account_identifier || '').trim();
    asset.notes = String(body.notes || '').trim();
    asset.updated_at = nowIso();
    return res.json({ success: true, message: 'Digital asset updated.', asset });
  }

  if (req.method === 'DELETE') {
    const id = Number(req.query.id || body.id || 0);
    const idx = db.assets.findIndex((a) => a.id === id && a.user_id === user.id);
    if (idx === -1) return res.status(404).json({ success: false, error: 'Digital asset not found.' });
    db.assets.splice(idx, 1);
    db.wishes = db.wishes.filter((w) => !(w.asset_id === id && w.user_id === user.id));
    return res.json({ success: true, message: 'Digital asset removed from your vault.' });
  }

  return res.status(405).json({ success: false, error: 'Method not allowed.' });
});

// 4. wishes.php / wishes
apiRouter.all(['/wishes.php', '/wishes'], (req, res) => {
  const user = requireUser(req, res);
  if (!user) return;
  const allowedActions = [
    'preserve_account',
    'preserve_memories',
    'share_information',
    'request_memorialization',
    'request_deletion',
  ];

  if (req.method === 'GET') {
    const items = db.assets
      .filter((a) => a.user_id === user.id)
      .sort((a, b) => b.id - a.id)
      .map((a) => {
        const w = db.wishes.find((x) => x.asset_id === a.id && x.user_id === user.id);
        const c = w?.assigned_contact_id
          ? db.contacts.find((tc) => tc.id === w.assigned_contact_id && tc.user_id === user.id)
          : null;
        return {
          asset_id: a.id,
          asset_name: a.asset_name,
          platform: a.platform,
          category: a.category,
          account_identifier: a.account_identifier,
          wish_id: w?.id || null,
          action_type: w?.action_type || null,
          custom_instructions: w?.custom_instructions || '',
          assigned_contact_id: w?.assigned_contact_id || null,
          assigned_contact_name: c?.name || null,
        };
      });
    const contacts = db.contacts.filter((c) => c.user_id === user.id);
    return res.json({ success: true, items, contacts });
  }

  if (!verifyCsrf(req, res)) return;
  const body = req.body || {};

  if (req.method === 'POST' || req.method === 'PUT') {
    const asset_id = Number(body.asset_id || 0);
    const action_type = String(body.action_type || '').trim();
    const custom_instructions = String(body.custom_instructions || '').trim();
    const assigned_contact_id = body.assigned_contact_id ? Number(body.assigned_contact_id) : null;

    if (!allowedActions.includes(action_type)) {
      return res.status(422).json({ success: false, error: 'Please select a valid final wish action.' });
    }
    const asset = db.assets.find((a) => a.id === asset_id && a.user_id === user.id);
    if (!asset) return res.status(404).json({ success: false, error: 'Digital asset not found.' });

    const existing = db.wishes.find((w) => w.asset_id === asset_id && w.user_id === user.id);
    if (existing) {
      existing.action_type = action_type;
      existing.custom_instructions = custom_instructions;
      existing.assigned_contact_id = assigned_contact_id;
      existing.updated_at = nowIso();
      return res.json({ success: true, message: 'Final wish instructions saved.', wish: existing });
    }

    const created: WishRow = {
      id: db.seq.wishes++,
      user_id: user.id,
      asset_id,
      assigned_contact_id,
      action_type,
      custom_instructions,
      created_at: nowIso(),
      updated_at: nowIso(),
    };
    db.wishes.push(created);
    return res.json({ success: true, message: 'Final wish instructions saved.', wish: created });
  }

  if (req.method === 'DELETE') {
    const id = Number(req.query.id || body.id || 0);
    const idx = db.wishes.findIndex((w) => w.id === id && w.user_id === user.id);
    if (idx === -1) return res.status(404).json({ success: false, error: 'Final wish not found.' });
    db.wishes.splice(idx, 1);
    return res.json({ success: true, message: 'Final wish removed.' });
  }

  return res.status(405).json({ success: false, error: 'Method not allowed.' });
});

// 5. contacts.php / contacts
apiRouter.all(['/contacts.php', '/contacts'], (req, res) => {
  const action = String(req.query.action || '');

  // Public invitation view
  if (req.method === 'GET' && action === 'invitation') {
    const token = String(req.query.token || '').trim();
    const contact = db.contacts.find((c) => c.invitation_token === token);
    if (!contact) return res.status(404).json({ success: false, error: 'Invitation link is invalid.' });
    const owner = db.users.find((u) => u.id === contact.user_id);
    return res.json({
      success: true,
      invitation: {
        id: contact.id,
        name: contact.name,
        email: contact.email,
        relationship: contact.relationship,
        invitation_status: contact.invitation_status,
        responded_at: contact.responded_at,
        owner_name: owner?.full_name || 'Vault Owner',
        owner_handle: owner?.user_handle || '',
      },
    });
  }

  // Public invitation response
  if (req.method === 'POST' && action === 'respond_invitation') {
    if (!verifyCsrf(req, res)) return;
    const token = String(req.body?.token || '').trim();
    const decision = String(req.body?.decision || '').trim();
    if (!['accepted', 'declined'].includes(decision)) {
      return res.status(422).json({ success: false, error: 'Decision must be accepted or declined.' });
    }
    const contact = db.contacts.find((c) => c.invitation_token === token);
    if (!contact) return res.status(404).json({ success: false, error: 'Invitation not found.' });
    contact.invitation_status = decision as 'accepted' | 'declined';
    contact.responded_at = nowIso();
    contact.updated_at = nowIso();
    return res.json({
      success: true,
      message: `Invitation marked as ${decision}. Note: this does not grant access to private vault records.`,
      invitation: contact,
    });
  }

  const user = requireUser(req, res);
  if (!user) return;

  if (req.method === 'GET') {
    const contacts = db.contacts.filter((c) => c.user_id === user.id).sort((a, b) => b.id - a.id);
    return res.json({ success: true, contacts });
  }

  if (!verifyCsrf(req, res)) return;
  const body = req.body || {};

  if (req.method === 'POST') {
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const phone = String(body.phone || '').trim();
    const relationship = String(body.relationship || '').trim();
    if (!name || !email.includes('@') || !relationship) {
      return res.status(422).json({ success: false, error: 'Name, valid email, and relationship are required.' });
    }
    if (db.contacts.some((c) => c.user_id === user.id && c.email.toLowerCase() === email)) {
      return res.status(409).json({ success: false, error: 'This contact email is already registered.' });
    }
    const created: ContactRow = {
      id: db.seq.contacts++,
      user_id: user.id,
      name,
      email,
      phone,
      relationship,
      invitation_token: 'mv_inv_' + crypto.randomBytes(10).toString('hex'),
      invitation_status: 'pending',
      responded_at: null,
      created_at: nowIso(),
      updated_at: nowIso(),
    };
    db.contacts.push(created);
    logNotification(
      user.id,
      email,
      'trusted_contact',
      'contact_invitation',
      `${user.full_name} invited you as a Trusted Contact on Memory Vault`,
      `Hello ${name}, ${user.full_name} designated you as a Trusted Contact. Accepting does not grant automatic vault access.`,
      '',
      false
    );
    return res.status(201).json({ success: true, message: 'Trusted contact invited.', contact: created });
  }

  if (req.method === 'PUT') {
    const id = Number(body.id || 0);
    const contact = db.contacts.find((c) => c.id === id && c.user_id === user.id);
    if (!contact) return res.status(404).json({ success: false, error: 'Trusted contact not found.' });

    if (body.action === 'simulate_status') {
      const st = String(body.invitation_status || '');
      if (!['pending', 'accepted', 'declined'].includes(st)) {
        return res.status(422).json({ success: false, error: 'Invalid status.' });
      }
      contact.invitation_status = st as 'pending' | 'accepted' | 'declined';
      contact.responded_at = st === 'pending' ? null : nowIso();
      contact.updated_at = nowIso();
      return res.json({
        success: true,
        message: `Invitation status updated to ${st}. Private vault data remains protected.`,
        contact,
      });
    }

    contact.name = String(body.name || '').trim();
    contact.email = String(body.email || '').trim().toLowerCase();
    contact.phone = String(body.phone || '').trim();
    contact.relationship = String(body.relationship || '').trim();
    contact.updated_at = nowIso();
    return res.json({ success: true, message: 'Trusted contact updated.', contact });
  }

  if (req.method === 'DELETE') {
    const id = Number(req.query.id || body.id || 0);
    const idx = db.contacts.findIndex((c) => c.id === id && c.user_id === user.id);
    if (idx === -1) return res.status(404).json({ success: false, error: 'Trusted contact not found.' });
    db.contacts.splice(idx, 1);
    return res.json({ success: true, message: 'Trusted contact removed.' });
  }

  return res.status(405).json({ success: false, error: 'Method not allowed.' });
});

// 6. memories.php / memories
apiRouter.all(['/memories.php', '/memories'], (req, res) => {
  const user = requireUser(req, res);
  if (!user) return;

  if (req.method === 'GET') {
    const memories = db.memories
      .filter((m) => m.user_id === user.id)
      .sort((a, b) => b.id - a.id)
      .map((m) => {
        const c = m.trusted_contact_id
          ? db.contacts.find((tc) => tc.id === m.trusted_contact_id && tc.user_id === user.id)
          : null;
        return {
          ...m,
          contact_name: c?.name || null,
          contact_email: c?.email || null,
          contact_relationship: c?.relationship || null,
        };
      });
    const contacts = db.contacts.filter((c) => c.user_id === user.id);
    return res.json({ success: true, memories, contacts });
  }

  if (!verifyCsrf(req, res)) return;
  const body = req.body || {};

  if (req.method === 'POST') {
    const title = String(body.title || '').trim();
    const message_body = String(body.message_body || '').trim();
    const trusted_contact_id = body.trusted_contact_id ? Number(body.trusted_contact_id) : null;
    const custom_recipient = String(body.custom_recipient || '').trim();
    const release_condition = String(body.release_condition || 'Upon verified admin approval').trim();

    if (!title || !message_body || (!trusted_contact_id && !custom_recipient)) {
      return res.status(422).json({ success: false, error: 'Title, message body, and a recipient are required.' });
    }
    const created: MemoryRow = {
      id: db.seq.memories++,
      user_id: user.id,
      trusted_contact_id,
      custom_recipient,
      title,
      message_body,
      release_condition,
      created_at: nowIso(),
      updated_at: nowIso(),
    };
    db.memories.push(created);
    return res.status(201).json({ success: true, message: 'Letter preserved in your vault.', memory: created });
  }

  if (req.method === 'PUT') {
    const id = Number(body.id || 0);
    const mem = db.memories.find((m) => m.id === id && m.user_id === user.id);
    if (!mem) return res.status(404).json({ success: false, error: 'Memory not found.' });
    mem.title = String(body.title || '').trim();
    mem.message_body = String(body.message_body || '').trim();
    mem.trusted_contact_id = body.trusted_contact_id ? Number(body.trusted_contact_id) : null;
    mem.custom_recipient = String(body.custom_recipient || '').trim();
    mem.release_condition = String(body.release_condition || 'Upon verified admin approval').trim();
    mem.updated_at = nowIso();
    return res.json({ success: true, message: 'Letter updated.', memory: mem });
  }

  if (req.method === 'DELETE') {
    const id = Number(req.query.id || body.id || 0);
    const idx = db.memories.findIndex((m) => m.id === id && m.user_id === user.id);
    if (idx === -1) return res.status(404).json({ success: false, error: 'Memory not found.' });
    db.memories.splice(idx, 1);
    return res.json({ success: true, message: 'Letter deleted from vault.' });
  }

  return res.status(405).json({ success: false, error: 'Method not allowed.' });
});

// 7. legacy_requests.php / legacy_requests
apiRouter.all(['/legacy_requests.php', '/legacy_requests'], (req, res) => {
  const action = String(req.query.action || '');

  if (req.method === 'GET' && action === 'summary') {
    const user = requireUser(req, res);
    if (!user) return;
    const plan = db.plans.find((p) => p.user_id === user.id) || {
      first_reminder_days: 30,
      second_reminder_days: 35,
      final_reminder_days: 40,
      trusted_alert_days: 45,
      general_guidance: '',
    };
    const assets = db.assets
      .filter((a) => a.user_id === user.id)
      .map((a) => {
        const w = db.wishes.find((x) => x.asset_id === a.id && x.user_id === user.id);
        const c = w?.assigned_contact_id ? db.contacts.find((tc) => tc.id === w.assigned_contact_id) : null;
        return {
          ...a,
          action_type: w?.action_type || null,
          custom_instructions: w?.custom_instructions || '',
          assigned_contact_name: c?.name || null,
        };
      });
    const contacts = db.contacts.filter((c) => c.user_id === user.id);
    const memories = db.memories
      .filter((m) => m.user_id === user.id)
      .map((m) => {
        const c = m.trusted_contact_id ? db.contacts.find((tc) => tc.id === m.trusted_contact_id) : null;
        return { ...m, contact_name: c?.name || null, contact_relationship: c?.relationship || null };
      });
    return res.json({
      success: true,
      summary: {
        generated_at: nowIso(),
        user: {
          id: user.id,
          user_handle: user.user_handle,
          full_name: user.full_name,
          email: user.email,
          last_check_in: user.last_check_in,
          escalation_stage: user.escalation_stage,
          ...plan,
        },
        assets,
        contacts,
        memories,
      },
    });
  }

  if (req.method === 'GET' && action === 'lookup') {
    const contactEmail = String(req.query.contact_email || '').trim().toLowerCase();
    const ownerIdentifier = String(req.query.owner_identifier || '').trim().toLowerCase();
    const owner = db.users.find(
      (u) => u.email.toLowerCase() === ownerIdentifier || u.user_handle.toLowerCase() === ownerIdentifier
    );
    if (!owner) return res.status(404).json({ success: false, error: 'No matching vault owner found.' });

    const requests = db.requests
      .filter((r) => r.user_id === owner.id && r.requester_email.toLowerCase() === contactEmail)
      .sort((a, b) => b.id - a.id)
      .map((r) => {
        const contact = db.contacts.find((c) => c.id === r.trusted_contact_id);
        const isApproved = r.status === 'approved';
        const authorized_memories = isApproved
          ? db.memories.filter((m) => m.user_id === owner.id && m.trusted_contact_id === r.trusted_contact_id)
          : [];
        const authorized_wishes = isApproved
          ? db.wishes
              .filter((w) => w.user_id === owner.id && w.assigned_contact_id === r.trusted_contact_id)
              .map((w) => {
                const a = db.assets.find((x) => x.id === w.asset_id);
                return {
                  asset_name: a?.asset_name || '',
                  platform: a?.platform || '',
                  category: a?.category || '',
                  account_identifier: a?.account_identifier || '',
                  notes: a?.notes || '',
                  action_type: w.action_type,
                  custom_instructions: w.custom_instructions,
                };
              })
          : [];

        return {
          ...r,
          contact_name: contact?.name || 'Trusted Contact',
          relationship: contact?.relationship || '',
          authorized_memories,
          authorized_wishes,
        };
      });

    return res.json({
      success: true,
      owner: { full_name: owner.full_name, user_handle: owner.user_handle },
      requests,
    });
  }

  if (req.method === 'POST' && action === 'submit') {
    if (!verifyCsrf(req, res)) return;
    const contactEmail = String(req.body?.contact_email || '').trim().toLowerCase();
    const ownerIdentifier = String(req.body?.owner_identifier || '').trim().toLowerCase();
    const reason = String(req.body?.reason || '').trim();
    const verificationNote = String(req.body?.verification_note || '').trim();

    if (!contactEmail.includes('@') || !ownerIdentifier || !reason || verificationNote.length < 10) {
      return res.status(422).json({
        success: false,
        error: 'Please enter all fields and a verification note of at least 10 characters.',
      });
    }
    const owner = db.users.find(
      (u) => u.email.toLowerCase() === ownerIdentifier || u.user_handle.toLowerCase() === ownerIdentifier
    );
    if (!owner) {
      return res.status(404).json({ success: false, error: 'Vault owner and trusted contact could not be verified.' });
    }
    const contact = db.contacts.find(
      (c) => c.user_id === owner.id && c.email.toLowerCase() === contactEmail
    );
    if (!contact) {
      return res.status(403).json({
        success: false,
        error: 'Only registered Trusted Contacts of this vault owner may submit a legacy access request.',
      });
    }
    if (contact.invitation_status === 'declined') {
      return res.status(403).json({ success: false, error: 'Declined contacts cannot submit requests.' });
    }
    const existingPending = db.requests.find(
      (r) => r.user_id === owner.id && r.trusted_contact_id === contact.id && r.status === 'pending'
    );
    if (existingPending) {
      return res.status(409).json({
        success: false,
        error: `A pending request (${existingPending.request_code}) is already awaiting review.`,
      });
    }

    const request_code = `REQ-${new Date().getUTCFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
    const created: LegacyRequestRow = {
      id: db.seq.requests++,
      request_code,
      user_id: owner.id,
      trusted_contact_id: contact.id,
      requester_email: contactEmail,
      reason,
      verification_note: verificationNote,
      status: 'pending',
      admin_remarks: '',
      reviewed_by: null,
      reviewed_at: null,
      created_at: nowIso(),
      updated_at: nowIso(),
    };
    db.requests.push(created);
    logNotification(
      owner.id,
      contactEmail,
      'trusted_contact',
      'legacy_request_submitted',
      `Legacy Access Request Received (${request_code})`,
      `Your request (${request_code}) is pending administrative verification. No private vault data is released automatically.`,
      '',
      false
    );
    return res.status(201).json({
      success: true,
      message: `Request ${request_code} submitted for administrative verification. Private data remains locked until explicit admin approval.`,
      request: created,
    });
  }

  return res.status(400).json({ success: false, error: 'Unsupported request.' });
});

// 8. admin.php / admin
apiRouter.all(['/admin.php', '/admin'], (req, res) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const action = String(req.query.action || '');

  if (req.method === 'GET') {
    const filter = String(req.query.status || 'all');
    const counts = { pending: 0, approved: 0, rejected: 0 };
    for (const r of db.requests) counts[r.status]++;

    const requests = db.requests
      .filter((r) => filter === 'all' || r.status === filter)
      .sort((a, b) => (a.status === 'pending' ? -1 : 1) - (b.status === 'pending' ? -1 : 1) || b.id - a.id)
      .map((r) => {
        const owner = db.users.find((u) => u.id === r.user_id)!;
        const contact = db.contacts.find((c) => c.id === r.trusted_contact_id)!;
        const reviewer = r.reviewed_by ? db.admins.find((a) => a.id === r.reviewed_by) : null;
        return {
          ...r,
          owner_name: owner.full_name,
          owner_email: owner.email,
          owner_handle: owner.user_handle,
          owner_last_check_in: owner.last_check_in,
          owner_escalation_stage: owner.escalation_stage,
          owner_days_inactive: daysInactiveFor(owner),
          contact_name: contact.name,
          contact_email: contact.email,
          contact_phone: contact.phone,
          contact_relationship: contact.relationship,
          contact_invitation_status: contact.invitation_status,
          reviewer_name: reviewer?.full_name || null,
          authorized_memories_count: db.memories.filter(
            (m) => m.user_id === r.user_id && m.trusted_contact_id === r.trusted_contact_id
          ).length,
          authorized_wishes_count: db.wishes.filter(
            (w) => w.user_id === r.user_id && w.assigned_contact_id === r.trusted_contact_id
          ).length,
        };
      });

    const audit_logs = db.audits.slice(0, 20).map((a) => {
      const adm = db.admins.find((x) => x.id === a.admin_id);
      const reqRow = db.requests.find((x) => x.id === a.legacy_request_id);
      return {
        ...a,
        admin_name: adm?.full_name || 'Admin',
        admin_email: adm?.email || '',
        request_code: reqRow?.request_code || null,
      };
    });

    return res.json({
      success: true,
      admin: { id: admin.id, full_name: admin.full_name, email: admin.email, role: admin.role },
      stats: {
        ...counts,
        total_users: db.users.length,
        total_notifications: db.notifications.length,
      },
      requests,
      audit_logs,
      notifications: db.notifications.slice(0, 15),
    });
  }

  if (req.method === 'POST' && action === 'review') {
    if (!verifyCsrf(req, res)) return;
    const request_id = Number(req.body?.request_id || 0);
    const decision = String(req.body?.decision || '');
    const admin_remarks = String(req.body?.admin_remarks || '').trim();
    if (!['approved', 'rejected'].includes(decision) || admin_remarks.length < 4) {
      return res.status(422).json({
        success: false,
        error: 'Valid decision and review remarks (minimum 4 characters) are required.',
      });
    }
    const reqRow = db.requests.find((r) => r.id === request_id);
    if (!reqRow) return res.status(404).json({ success: false, error: 'Request not found.' });

    reqRow.status = decision as 'approved' | 'rejected';
    reqRow.admin_remarks = admin_remarks;
    reqRow.reviewed_by = admin.id;
    reqRow.reviewed_at = nowIso();
    reqRow.updated_at = nowIso();

    db.audits.unshift({
      id: db.seq.audits++,
      admin_id: admin.id,
      legacy_request_id: reqRow.id,
      action: `request_${decision}`,
      remarks: admin_remarks,
      created_at: nowIso(),
    });

    logNotification(
      reqRow.user_id,
      reqRow.requester_email,
      'trusted_contact',
      `legacy_request_${decision}`,
      `Legacy Access Request ${decision.toUpperCase()} (${reqRow.request_code})`,
      `Your legacy access request ${reqRow.request_code} was ${decision}. Remarks: ${admin_remarks}`,
      '',
      false
    );

    return res.json({
      success: true,
      message: `Request ${reqRow.request_code} marked as ${decision} and recorded in the audit log.`,
    });
  }

  return res.status(405).json({ success: false, error: 'Method not allowed.' });
});

// Mount API mirror routes under both /api (clean HTTPS preview routes) and /MEMORY-VAULT/backend/api
app.use('/api', apiRouter);
app.use('/MEMORY-VAULT/backend/api', apiRouter);

// Cron mirror endpoint
app.all(['/api/cron/check_inactivity', '/MEMORY-VAULT/backend/cron/check_inactivity.php'], (req, res) => {
  const sess = getSession(req);
  if (!sess.userId && !sess.adminId) {
    return res.status(401).json({ success: false, error: 'Authentication required.' });
  }
  const results = db.users.map((u) => evaluateInactivityForUser(u));
  return res.json({ success: true, evaluated_at: nowIso(), results });
});

// Serve the pure HTML/CSS/Vanilla JS Memory Vault frontend directly
app.use('/MEMORY-VAULT/frontend', express.static(MEMORY_VAULT_FRONTEND));
app.use('/src/assets', express.static(path.resolve(__dirname, 'src', 'assets')));

// Redirect root directly to the Memory Vault landing page so preview loads seamlessly
app.get('/', (_req, res) => {
  res.redirect('/MEMORY-VAULT/frontend/index.html');
});

// Fallback for any clean page path like /dashboard.html
app.get('/:page.html', (req, res, next) => {
  const candidate = path.resolve(MEMORY_VAULT_FRONTEND, `${req.params.page}.html`);
  if (candidate.startsWith(MEMORY_VAULT_FRONTEND + path.sep) && fs.existsSync(candidate)) {
    return res.redirect(`/MEMORY-VAULT/frontend/${req.params.page}.html`);
  }
  return next();
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Memory Vault live preview server running at http://0.0.0.0:${PORT}/MEMORY-VAULT/frontend/index.html`);
});
