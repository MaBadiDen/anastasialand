import dotenv from 'dotenv';
import { z } from 'zod';
import fs from 'fs';
import path from 'path';

dotenv.config();

const Bool = z.union([
  z.string().transform((v) => /^(1|true|yes)$/i.test(v)),
  z.boolean()
]).transform((v) => Boolean(v));

const Int = z.preprocess((v) => (v === undefined || v === '' ? undefined : Number(v)), z.number().int());

const EnvSchema = z.object({
  NODE_ENV: z.enum(['production', 'development', 'test']).default('development'),
  PORT: Int.default(3000),
  COOKIE_SECURE: z.string().optional(),
  TRUST_PROXY: z.string().optional(),
  DEBUG_AUTH: z.string().optional(),
  PUBLIC_URL: z.string().url().optional(),
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: Int.optional(),
  SMTP_SECURE: z.string().optional(),
  SMTP_TLS_REJECT_UNAUTH: z.string().optional(),
  SMTP_MAX_CONN: Int.optional(),
  SMTP_MAX_MSG: Int.optional(),
  MAIL_USER: z.string().optional(),
  MAIL_PASS: z.string().optional(),
  // Google Calendar (service account) placeholders
  GCAL_PROJECT_ID: z.string().optional(),
  GCAL_EMAIL: z.string().optional(),
  GCAL_PRIVATE_KEY: z.string().optional(),
  GCAL_CALENDAR_ID: z.string().optional(),
});

const env = EnvSchema.parse(process.env);

const isProd = env.NODE_ENV === 'production';
const isTest = env.NODE_ENV === 'test';

const cookieSecure = (env.COOKIE_SECURE ?? (isProd ? 'true' : 'false')) === 'true';
const trustProxy = (env.TRUST_PROXY ?? '0') === '1' || /^(true|yes)$/i.test(env.TRUST_PROXY || '');
const debugAuth = (env.DEBUG_AUTH ?? '0') === '1' || /^(true|yes)$/i.test(env.DEBUG_AUTH || '');

const publicUrl = env.PUBLIC_URL || `http://localhost:${env.PORT}`;

export const config = {
  env: env.NODE_ENV,
  isProd,
  isTest,
  port: env.PORT,
  cookieSecure,
  trustProxy,
  debugAuth,
  publicUrl,
  assetVersion: (() => {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
      return String(pkg.version || '1.0.0');
    } catch {
      return '1.0.0';
    }
  })(),
  smtp: {
    host: env.SMTP_HOST || 'smtp.mail.ru',
    port: env.SMTP_PORT ?? 465,
    secure: (env.SMTP_SECURE ?? 'true') === 'true',
    tlsRejectUnauthorized: (env.SMTP_TLS_REJECT_UNAUTH ?? 'true') === 'true',
    user: env.MAIL_USER,
    pass: env.MAIL_PASS,
    maxConnections: env.SMTP_MAX_CONN ?? 2,
    maxMessages: env.SMTP_MAX_MSG ?? 20,
  }
};

export type AppConfig = typeof config;
