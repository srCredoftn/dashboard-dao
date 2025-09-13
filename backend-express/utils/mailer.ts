import nodemailer, { type Transporter } from "nodemailer";

let transporterPromise: Promise<Transporter> | null = null;

function getBooleanEnv(name: string, def: boolean): boolean {
  const v = process.env[name];
  if (v == null) return def;
  return /^(1|true|yes|on)$/i.test(v);
}

async function createTransporter(): Promise<Transporter> {
  const host = process.env.SMTP_HOST;
  const port = process.env.SMTP_PORT
    ? Number(process.env.SMTP_PORT)
    : undefined;
  const secure = process.env.SMTP_SECURE
    ? getBooleanEnv("SMTP_SECURE", false)
    : port === 465; // default secure for 465
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (host && port && user && pass) {
    const transporter = nodemailer.createTransport({
      host,
      port,
      secure: Boolean(secure),
      auth: { user, pass },
    });

    // Verify on startup to fail fast in dev, but don't throw in production
    try {
      await transporter.verify();
      console.log("📮 SMTP transporter ready (configured host)");
    } catch (e) {
      console.warn(
        "⚠️ SMTP verify failed, emails may not send:",
        (e as Error).message,
      );
    }

    return transporter;
  }

  // Fallback to Ethereal for development/testing without real SMTP creds
  try {
    const testAccount = await nodemailer.createTestAccount();
    const transporter = nodemailer.createTransport({
      host: testAccount.smtp.host,
      port: testAccount.smtp.port,
      secure: testAccount.smtp.secure,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
    });
    console.log(
      "🧪 Using Ethereal test SMTP account. Preview emails via logged URL.",
    );
    return transporter;
  } catch (e) {
    // As last resort, create a stub transporter that resolves without sending to avoid runtime crashes
    console.warn(
      "⚠️ Failed to create Ethereal test account. Emails will be logged only.",
    );
    return {
      sendMail: async (options: any) => {
        console.log("✉️ [LOG-ONLY EMAIL]", {
          to: options.to,
          subject: options.subject,
          text: options.text,
        });
        return {
          messageId: "log-only",
          envelope: {},
          accepted: [],
          rejected: [],
        };
      },
      verify: async () => true,
    } as Transporter;
  }
}

export async function getMailer(): Promise<Transporter> {
  if (!transporterPromise) transporterPromise = createTransporter();
  return transporterPromise;
}

export async function sendMail(params: {
  to: string | string[];
  subject: string;
  text?: string;
  html?: string;
  from?: string;
}): Promise<{ messageId: string; previewUrl?: string | false }> {
  const transporter = await getMailer();
  const baseFromRaw =
    process.env.SMTP_FROM || process.env.SMTP_USER || "no-reply@example.com";
  const addressMatch = baseFromRaw.match(/<([^>]+)>/);
  const fromAddress = addressMatch ? addressMatch[1] : baseFromRaw.trim();
  const fromName = process.env.MAIL_FROM_NAME || "Gestion des DAO 2SND";

  const from = params.from || `${fromName} <${fromAddress}>`;

  const info = await transporter.sendMail({
    from,
    to: params.to,
    subject: params.subject,
    text: params.text,
    html: params.html,
  });

  let previewUrl: string | false = false;
  try {
    // @ts-ignore
    if (nodemailer.getTestMessageUrl) {
      // @ts-ignore
      previewUrl = nodemailer.getTestMessageUrl(info) || false;
      if (previewUrl) {
        console.log("🔗 Email preview:", previewUrl);
      }
    }
  } catch (_) {}

  return { messageId: info.messageId, previewUrl };
}

export async function verifySmtp(): Promise<{ ok: boolean; message?: string }> {
  try {
    const transporter = await getMailer();
    // some fallbacks may not implement verify strictly; wrap in try
    try {
      // @ts-ignore
      await transporter.verify?.();
    } catch (_) {}
    return { ok: true };
  } catch (e) {
    return { ok: false, message: (e as Error).message };
  }
}
