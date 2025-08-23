import { NextFunction, Request, Response } from 'express';
import fs from 'fs';
import { z } from 'zod';

export type ZodSchema<T> = z.ZodType<T>;

export function validateBody<T>(schema: ZodSchema<T>, fallbackPath: string, opts?: { cleanupFileOnFail?: boolean; preserveForm?: { key: string; pick: string[] } }) {
  return (req: Request, res: Response, next: NextFunction) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      const wantsJSON = (req as any).xhr || (req.get('accept') || '').includes('application/json');
      if (opts?.cleanupFileOnFail && (req as any).file && (req as any).file.path) {
        try { fs.unlinkSync((req as any).file.path); } catch {}
      }
      // Optionally preserve selected form fields in session to refill the form after redirect
      if (opts?.preserveForm && opts.preserveForm.key && Array.isArray(opts.preserveForm.pick)) {
        try {
          const store: Record<string, any> = {};
          for (const k of opts.preserveForm.pick) {
            if (Object.prototype.hasOwnProperty.call(req.body, k)) {
              (store as any)[k] = (req.body as any)[k];
            }
          }
          (req as any).session[opts.preserveForm.key] = store;
        } catch {}
      }
      const first = parsed.error.issues?.[0];
      const msg = first?.message || 'Некорректные данные формы';
      if (wantsJSON) {
        return res.status(400).json({ ok: false, message: msg });
      }
      return res.redirect(`${fallbackPath}?warning=${encodeURIComponent(msg)}`);
    }
    (req as any).body = parsed.data as any;
    return next();
  };
}

// Common schemas
export const loginSchema = z.object({
  username: z.string().min(3, 'Логин слишком короткий').max(50),
  password: z.string().min(6, 'Пароль слишком короткий').max(100)
});

// Password policy: 8-100 chars, must contain letters and at least one digit OR special symbol
const passwordPolicy = z.string()
  .min(8, 'Пароль должен быть не короче 8 символов')
  .max(100)
  .refine((p) => /[A-Za-z]/.test(p) && (/[0-9]/.test(p) || /[^A-Za-z0-9]/.test(p)), {
    message: 'Пароль должен содержать буквы и цифры или спецсимволы',
  });

export const registerSchema = z.object({
  username: z.string().min(3, 'Логин слишком короткий').max(50),
  password: passwordPolicy,
  email: z.string().email('Некорректный email')
});

export const forgotSchema = z.object({
  email: z.string().email('Некорректный email')
});

export const requestResetSchema = z.object({
  email: z.string().email('Некорректный email')
});

export const resetPasswordSchema = z.object({
  token: z.string().min(10, 'Некорректная ссылка'),
  password: passwordPolicy,
  confirm: z.string().min(8, 'Подтверждение пароля слишком короткое').max(100)
}).refine((d) => d.password === d.confirm, { message: 'Пароли не совпадают', path: ['confirm'] });

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Укажите текущий пароль'),
  newPassword: passwordPolicy,
  confirmPassword: z.string().min(8, 'Подтверждение пароля слишком короткое')
}).refine((data: { newPassword: string; confirmPassword: string }) => data.newPassword === data.confirmPassword, {
  message: 'Новые пароли не совпадают',
  path: ['confirmPassword']
});

export const topicSchema = z.object({
  name: z.string().trim().min(1, 'Название раздела обязательно').max(100)
});

export const deleteTopicSchema = z.object({
  id: z.preprocess((v: unknown) => Number(v as any), z.number().int().positive('Некорректный ID раздела'))
});

export const editUserSchema = z.object({
  username: z.string().min(3, 'Имя слишком короткое').max(50),
  email: z.string().email('Некорректный email'),
  password: passwordPolicy.optional().or(z.literal(''))
});

export const videoMetaSchema = z.object({
  title: z.string().trim().min(1, 'Название обязательно').max(200),
  topic: z.string().trim().min(1, 'Раздел обязателен').max(100),
  position: z.preprocess((v) => v === undefined || v === '' ? 0 : Number(v as any), z.number().int().min(0).max(100000)).optional()
});

export const auditClearSchema = z.object({
  mode: z.enum(['all', 'days']),
  days: z.preprocess((v: unknown) => v === '' || v === undefined ? undefined : Number(v as any), z.number().int().positive('Число дней должно быть положительным').optional())
}).refine((data) => data.mode === 'all' || typeof data.days === 'number', {
  message: 'Укажите количество дней',
  path: ['days']
});

// Video tests schemas
export const upsertVideoTestSchema = z.object({
  videoId: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный ID видео')),
  question: z.string().trim().min(1, 'Вопрос обязателен').max(500),
  options: z.array(z.string().trim().min(1)).min(2, 'Минимум два варианта').max(10, 'Слишком много вариантов'),
  answer: z.preprocess((v) => Number(v as any), z.number().int().min(0, 'Некорректный ответ')),
  position: z.preprocess((v) => v === undefined || v === '' ? 0 : Number(v as any), z.number().int().min(0)).optional()
}).refine((d) => d.answer < d.options.length, { message: 'Ответ вне диапазона вариантов', path: ['answer'] });

export const deleteVideoTestSchema = z.object({
  id: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный ID теста'))
});

export const updateVideoTestSchema = z.object({
  id: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный ID теста')),
  videoId: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный ID видео')),
  question: z.string().trim().min(1, 'Вопрос обязателен').max(500),
  options: z.array(z.string().trim().min(1)).min(2, 'Минимум два варианта').max(10, 'Слишком много вариантов'),
  answer: z.preprocess((v) => Number(v as any), z.number().int().min(0, 'Некорректный ответ')),
  position: z.preprocess((v) => v === undefined || v === '' ? 0 : Number(v as any), z.number().int().min(0)).optional()
}).refine((d) => d.answer < d.options.length, { message: 'Ответ вне диапазона вариантов', path: ['answer'] });

// Webinar tests schemas (for lecturer)
export const upsertWebinarTestSchema = z.object({
  webinarId: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный вебинар')),
  question: z.string().trim().min(1, 'Вопрос обязателен').max(500),
  options: z.array(z.string().trim().min(1)).min(2, 'Минимум два варианта').max(10, 'Слишком много вариантов'),
  answer: z.preprocess((v) => Number(v as any), z.number().int().min(0, 'Некорректный ответ')),
  position: z.preprocess((v) => v === undefined || v === '' ? 0 : Number(v as any), z.number().int().min(0)).optional()
}).refine((d) => d.answer < d.options.length, { message: 'Ответ вне диапазона вариантов', path: ['answer'] });

export const updateWebinarTestSchema = z.object({
  id: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный тест')),
  webinarId: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный вебинар')),
  question: z.string().trim().min(1, 'Вопрос обязателен').max(500),
  options: z.array(z.string().trim().min(1)).min(2, 'Минимум два варианта').max(10, 'Слишком много вариантов'),
  answer: z.preprocess((v) => Number(v as any), z.number().int().min(0, 'Некорректный ответ')),
  position: z.preprocess((v) => v === undefined || v === '' ? 0 : Number(v as any), z.number().int().min(0)).optional()
}).refine((d) => d.answer < d.options.length, { message: 'Ответ вне диапазона вариантов', path: ['answer'] });

export const deleteWebinarTestSchema = z.object({
  id: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный тест'))
});

// Lecturer/course schemas
export const courseSchema = z.object({
  name: z.string().trim().min(1, 'Название курса обязательно').max(100)
});

export const lecturerAccessSchema = z.object({
  username: z.string().min(3),
  courseId: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный курс'))
});

export const webinarToggleSchema = z.object({
  id: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный вебинар')),
  open: z.preprocess((v) => v === '1' || v === 1 || v === true || v === 'true' ? 1 : 0, z.number().int())
});

// Create webinar schema (course-only)
export const webinarAddSchema = z.object({
  summary: z.string().trim().min(1, 'Тема обязательна').max(200),
  description: z.string().trim().min(1, 'Описание обязательно').max(2000),
  start_time: z.string().trim().min(1, 'Время начала обязательно'),
  end_time: z.string().trim().min(1, 'Время окончания обязательно'),
  courseId: z.preprocess((v) => Number(v as any), z.number().int().positive('Укажите курс'))
});

// Groups management
export const groupSchema = z.object({
  name: z.string().trim().min(1, 'Название группы обязательно').max(100)
});
export const groupIdSchema = z.object({
  id: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректная группа'))
});
export const groupMembershipSchema = z.object({
  username: z.string().min(3, 'Некорректный пользователь'),
  groupId: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректная группа'))
});
export const groupRenameSchema = z.object({
  id: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректная группа')),
  name: z.string().trim().min(1, 'Название группы обязательно').max(100)
});

// Webinar attendees management
export const webinarAttendeeUserSchema = z.object({
  webinarId: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный вебинар')),
  username: z.string().min(3, 'Некорректный пользователь')
});
export const webinarAttendeeGroupSchema = z.object({
  webinarId: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректный вебинар')),
  groupId: z.preprocess((v) => Number(v as any), z.number().int().positive('Некорректная группа'))
});

// Admin: users CRUD
export const adminCreateUserSchema = z.object({
  username: z.string().trim().min(3, 'Логин слишком короткий').max(50),
  password: passwordPolicy,
  email: z.string().email('Некорректный email').optional().or(z.literal('')),
  role: z.enum(['user', 'lecturer', 'admin'])
});

export const adminUpdateUserSchema = z.object({
  username: z.string().trim().min(3, 'Некорректный пользователь').max(50),
  email: z.string().email('Некорректный email').optional().or(z.literal('')),
  role: z.enum(['user', 'lecturer', 'admin']),
  password: passwordPolicy.optional().or(z.literal(''))
});

export const adminDeleteUserSchema = z.object({
  username: z.string().trim().min(3, 'Некорректный пользователь').max(50)
});
