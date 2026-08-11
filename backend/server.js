const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");

const { Resend } = require("resend");
const QRCode = require("qrcode");
const app = express();
const PORT = process.env.PORT || 3000;
const PENDING_RESERVATION_MINUTES = Math.max(
  2,
  Number(process.env.PENDING_RESERVATION_MINUTES || 5)
);

const QR_STORAGE_RETENTION_DAYS = Math.max(
  1,
  Number(process.env.QR_STORAGE_RETENTION_DAYS || 30)
);

const PASSWORD_RESET_RETENTION_DAYS = Math.max(
  1,
  Number(process.env.PASSWORD_RESET_RETENTION_DAYS || 7)
);

const CLEANUP_INTERVAL_MS = Math.max(
  60_000,
  Number(process.env.CLEANUP_INTERVAL_MS || 15 * 60_000)
);

/*
==================================================
VARIABLES DE ENTORNO
==================================================
*/

const INITIAL_ADMIN_PASSWORD = process.env.ADMIN_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const RESEND_API_KEY = process.env.RESEND_API_KEY;

const ADMIN_RECOVERY_EMAIL = String(
  process.env.ADMIN_RECOVERY_EMAIL || ""
).trim().toLowerCase();

const ADMIN_RECOVERY_CODE_MINUTES = Math.max(
  5,
  Number(process.env.ADMIN_RECOVERY_CODE_MINUTES || 15)
);

const ADMIN_RECOVERY_MAX_ATTEMPTS = Math.max(
  3,
  Number(process.env.ADMIN_RECOVERY_MAX_ATTEMPTS || 5)
);

const RESEND_FROM_EMAIL =
  process.env.RESEND_FROM_EMAIL ||
  "Cine Manuel Nieves <onboarding@resend.dev>";

const resend = RESEND_API_KEY
  ? new Resend(RESEND_API_KEY)
  : null;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;
const SUPABASE_POSTERS_BUCKET =
  process.env.SUPABASE_POSTERS_BUCKET || "posters";
const SUPABASE_TRAILERS_BUCKET =
  process.env.SUPABASE_TRAILERS_BUCKET ||
  SUPABASE_POSTERS_BUCKET;

// PayPal y ATH Móvil
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || "";
const PAYPAL_MODE = String(process.env.PAYPAL_MODE || "sandbox").toLowerCase();
const PAYPAL_CURRENCY = String(process.env.PAYPAL_CURRENCY || "USD").toUpperCase();
const ATH_MOVIL_PHONE = process.env.ATH_MOVIL_PHONE || "";

const ATH_TEST_MODE =
  String(process.env.ATH_TEST_MODE || "false").toLowerCase() === "true";

const PAYPAL_API_BASE = PAYPAL_MODE === "live"
  ? "https://api-m.paypal.com"
  : "https://api-m.sandbox.paypal.com";

app.use(cors());
app.use(express.json());

if (!process.env.DATABASE_URL) {
  console.error("Falta la variable DATABASE_URL.");
  process.exit(1);
}

if (!INITIAL_ADMIN_PASSWORD) {
  console.error("Falta la variable ADMIN_KEY.");
  process.exit(1);
}

if (!SUPABASE_URL) {
  console.error("Falta la variable SUPABASE_URL.");
  process.exit(1);
}

if (!SUPABASE_SERVICE_ROLE_KEY) {
  console.error(
    "Falta la variable SUPABASE_SERVICE_ROLE_KEY."
  );
  process.exit(1);
}

/*
==================================================
CONEXIÃN CON POSTGRESQL
==================================================
*/

const useSSL =
  process.env.DATABASE_URL.includes("render.com") ||
  process.env.DATABASE_URL.includes("supabase.com");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSSL
    ? {
        rejectUnauthorized: false
      }
    : false
});

/*
==================================================
SUPABASE STORAGE
==================================================
*/

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  }
);

const posterUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 6 * 1024 * 1024
  },
  fileFilter: (req, file, callback) => {
    const allowedTypes = new Set([
      "image/jpeg",
      "image/png",
      "image/webp"
    ]);

    if (!allowedTypes.has(file.mimetype)) {
      callback(
        new Error(
          "El afiche debe ser JPG, PNG o WEBP."
        )
      );
      return;
    }

    callback(null, true);
  }
});

function extensionFromMimeType(mimeType) {
  const extensions = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp"
  };

  return extensions[mimeType] || "jpg";
}

const trailerUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024
  },
  fileFilter: (req, file, callback) => {
    const allowedTypes = new Set([
      "video/mp4",
      "video/webm",
      "video/quicktime"
    ]);

    if (!allowedTypes.has(file.mimetype)) {
      callback(
        new Error(
          "El trÃ¡iler debe ser MP4, WEBM o MOV."
        )
      );
      return;
    }

    callback(null, true);
  }
});

function trailerExtensionFromMimeType(mimeType) {
  const extensions = {
    "video/mp4": "mp4",
    "video/webm": "webm",
    "video/quicktime": "mov"
  };

  return extensions[mimeType] || "mp4";
}


function extractSupabaseObjectPath(publicUrl, bucketName) {
  const value = String(publicUrl || "").trim();

  if (!value || !bucketName) {
    return "";
  }

  try {
    const url = new URL(value);
    const marker = `/storage/v1/object/public/${bucketName}/`;
    const index = url.pathname.indexOf(marker);

    if (index === -1) {
      return "";
    }

    return decodeURIComponent(
      url.pathname.slice(index + marker.length)
    );
  } catch {
    return "";
  }
}

async function removeSupabaseObjects(bucketName, paths) {
  const uniquePaths = [
    ...new Set(
      (Array.isArray(paths) ? paths : [])
        .map((path) => String(path || "").trim())
        .filter(Boolean)
    )
  ];

  if (uniquePaths.length === 0) {
    return 0;
  }

  const { data, error } = await supabase.storage
    .from(bucketName)
    .remove(uniquePaths);

  if (error) {
    throw new Error(error.message);
  }

  return Array.isArray(data) ? data.length : uniquePaths.length;
}

async function deleteMovieStorageFiles(movie) {
  if (!movie) {
    return;
  }

  const posterPath = extractSupabaseObjectPath(
    movie.poster_url,
    SUPABASE_POSTERS_BUCKET
  );

  const trailerPath = extractSupabaseObjectPath(
    movie.trailer_url,
    SUPABASE_TRAILERS_BUCKET
  );

  if (SUPABASE_POSTERS_BUCKET === SUPABASE_TRAILERS_BUCKET) {
    await removeSupabaseObjects(
      SUPABASE_POSTERS_BUCKET,
      [posterPath, trailerPath]
    );
    return;
  }

  await Promise.all([
    removeSupabaseObjects(SUPABASE_POSTERS_BUCKET, [posterPath]),
    removeSupabaseObjects(SUPABASE_TRAILERS_BUCKET, [trailerPath])
  ]);
}

async function cleanupOldQrFiles() {
  const cutoff = new Date(
    Date.now() - QR_STORAGE_RETENTION_DAYS * 24 * 60 * 60 * 1000
  );

  let offset = 0;
  let deletedCount = 0;

  while (true) {
    const { data, error } = await supabase.storage
      .from(SUPABASE_POSTERS_BUCKET)
      .list("tickets", {
        limit: 100,
        offset,
        sortBy: { column: "created_at", order: "asc" }
      });

    if (error) {
      throw new Error(error.message);
    }

    const files = Array.isArray(data) ? data : [];

    if (files.length === 0) {
      break;
    }

    const oldPaths = files
      .filter((file) => {
        const createdAt = file?.created_at || file?.updated_at;
        if (!createdAt) return false;
        const fileDate = new Date(createdAt);
        return Number.isFinite(fileDate.getTime()) && fileDate < cutoff;
      })
      .map((file) => `tickets/${file.name}`)
      .filter(Boolean);

    if (oldPaths.length > 0) {
      deletedCount += await removeSupabaseObjects(
        SUPABASE_POSTERS_BUCKET,
        oldPaths
      );
    }

    if (files.length < 100) {
      break;
    }

    offset += 100;
  }

  return deletedCount;
}

/*
==================================================
CONTRASEÃA DEL ADMINISTRADOR
==================================================
*/

function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(derivedKey);
    });
  });
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await scryptAsync(password, salt);

  return {
    salt,
    hash: derivedKey.toString("hex")
  };
}

async function verifyPassword(password, storedSalt, storedHash) {
  const derivedKey = await scryptAsync(password, storedSalt);
  const storedBuffer = Buffer.from(storedHash, "hex");

  if (storedBuffer.length !== derivedKey.length) {
    return false;
  }

  return crypto.timingSafeEqual(storedBuffer, derivedKey);
}


function normalizeRecoveryEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function hashAdminRecoveryCode(email, code) {
  const secret =
    process.env.ADMIN_RECOVERY_SECRET ||
    INITIAL_ADMIN_PASSWORD;

  return crypto
    .createHmac("sha256", secret)
    .update(`${normalizeRecoveryEmail(email)}:${String(code || "")}`)
    .digest("hex");
}

function safeEqualHex(left, right) {
  try {
    const leftBuffer = Buffer.from(String(left || ""), "hex");
    const rightBuffer = Buffer.from(String(right || ""), "hex");

    if (
      leftBuffer.length === 0 ||
      leftBuffer.length !== rightBuffer.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(leftBuffer, rightBuffer);
  } catch {
    return false;
  }
}

async function sendAdminRecoveryEmail(code) {
  if (!resend) {
    throw new Error(
      "El servicio de correo no está configurado."
    );
  }

  if (!ADMIN_RECOVERY_EMAIL) {
    throw new Error(
      "Falta configurar ADMIN_RECOVERY_EMAIL."
    );
  }

  const { error } = await resend.emails.send({
    from: RESEND_FROM_EMAIL,
    to: [ADMIN_RECOVERY_EMAIL],
    subject: "Código para recuperar la contraseña del panel",
    html: `
      <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:28px;background:#0f172a;color:#ffffff;border-radius:16px;">
        <h1 style="margin-top:0;font-size:24px;">🔐 Recuperación del panel administrativo</h1>
        <p style="color:#cbd5e1;line-height:1.6;">
          Se solicitó restablecer la contraseña del panel administrativo
          del Cine Teatro Manuel Nieves Quintero.
        </p>
        <div style="margin:24px 0;padding:20px;text-align:center;background:#111827;border:1px solid #334155;border-radius:14px;">
          <div style="font-size:13px;color:#94a3b8;margin-bottom:8px;">
            Código de recuperación
          </div>
          <div style="font-size:36px;font-weight:900;letter-spacing:8px;">
            ${code}
          </div>
        </div>
        <p style="color:#cbd5e1;line-height:1.6;">
          Este código vence en ${ADMIN_RECOVERY_CODE_MINUTES} minutos
          y solo puede utilizarse una vez.
        </p>
        <p style="color:#94a3b8;font-size:13px;line-height:1.5;">
          Si tú no solicitaste este cambio, ignora este mensaje.
        </p>
      </div>
    `
  });

  if (error) {
    throw new Error(
      error.message || "No se pudo enviar el correo de recuperación."
    );
  }
}

function hashSessionToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}

async function getAdminCredentials() {
  const result = await pool.query(`
    SELECT password_salt, password_hash
    FROM admin_settings
    WHERE id = 1;
  `);

  return result.rows[0] || null;
}

async function isValidAdminPassword(password) {
  if (!password || typeof password !== "string") {
    return false;
  }

  const credentials = await getAdminCredentials();

  if (!credentials) {
    return false;
  }

  return verifyPassword(
    password,
    credentials.password_salt,
    credentials.password_hash
  );
}

async function requireAdmin(req, res, next) {
  try {
    const providedPassword = req.headers["x-admin-key"];
    const valid = await isValidAdminPassword(providedPassword);

    if (!valid) {
      return res.status(401).json({
        error: "Acceso denegado."
      });
    }

    next();
  } catch (error) {
    console.error("Error verificando acceso administrativo:", error);

    res.status(500).json({
      error: "No se pudo verificar el acceso administrativo."
    });
  }
}

async function requireEmployee(req, res, next) {
  try {
    const token = req.headers["x-employee-token"];
    if (!token || typeof token !== "string") {
      return res.status(401).json({ error: "Debes iniciar sesiÃ3n como empleado." });
    }
    const tokenHash = hashSessionToken(token);
    const result = await pool.query(`
      SELECT
        e.id,
        e.name,
        e.username,
        e.active,
        s.created_at AS session_created_at,
        s.expires_at AS session_expires_at
      FROM employee_sessions s
      JOIN employees e ON e.id = s.employee_id
      WHERE
        s.token_hash = $1
        AND s.expires_at > NOW()
        AND e.active = TRUE;
    `, [tokenHash]);
    if (result.rowCount === 0) {
      return res.status(401).json({ error: "La sesiÃ3n del empleado expirÃ3 o no es vÃ¡lida." });
    }
    req.employee = result.rows[0];
    req.employeeTokenHash = tokenHash;
    next();
  } catch (error) {
    console.error("Error verificando al empleado:", error);
    res.status(500).json({ error: "No se pudo verificar la sesiÃ3n del empleado." });
  }
}

/*
==================================================
PAYPAL
==================================================
*/

function paypalIsConfigured() {
  return Boolean(PAYPAL_CLIENT_ID && PAYPAL_CLIENT_SECRET);
}

async function paypalRequest(path, options = {}) {
  if (!paypalIsConfigured()) {
    throw new Error("PayPal no está configurado en el servidor.");
  }

  const basicAuth = Buffer.from(
    `${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`
  ).toString("base64");

  const tokenResponse = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "grant_type=client_credentials"
  });

  const tokenData = await tokenResponse.json().catch(() => ({}));

  if (!tokenResponse.ok || !tokenData.access_token) {
    console.error("Error obteniendo token de PayPal:", tokenData);
    throw new Error("No se pudo autenticar con PayPal.");
  }

  const response = await fetch(`${PAYPAL_API_BASE}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    console.error("Error de PayPal:", response.status, data);
    const detail = Array.isArray(data.details) && data.details[0]
      ? data.details[0].description || data.details[0].issue
      : "";
    throw new Error(detail || data.message || "PayPal rechazó la solicitud.");
  }

  return data;
}

/*
==================================================
FORMATEADORES
==================================================
*/

async function generateUniqueManualCode(client) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const code = String(
      crypto.randomInt(0, 100000)
    ).padStart(5, "0");

    const existing = await client.query(
      `
        SELECT 1
        FROM tickets
        WHERE manual_code = $1
        LIMIT 1;
      `,
      [code]
    );

    if (existing.rowCount === 0) {
      return code;
    }
  }

  throw new Error(
    "No se pudo generar un cÃ3digo manual Ãonico."
  );
}

function formatTicket(row) {
  return {
    id: row.id,
    movie: row.movie,
    time: row.show_time,
    seats: row.seats,
    total: Number(row.total),
    customer: row.customer,
    paymentStatus: row.payment_status,
    paymentMethod: row.customer?.paymentMethod || "",
    qr: row.qr,
    manualCode: row.manual_code || "",
    used: row.used,
    created: row.created_at,
    checkin: row.checkin_at,
    ticketTypes: row.ticket_breakdown || {
      adult: Array.isArray(row.seats) ? row.seats.length : 0,
      child: 0,
      senior: 0
    }
  };
}


function formatTicketDateTime(value) {
  const rawValue = String(value || "").trim();

  if (!rawValue) {
    return {
      date: "Fecha no disponible",
      time: "Hora no disponible",
      full: "Fecha y hora no disponibles"
    };
  }

  let year;
  let month;
  let day;

  const isoDateMatch = rawValue.match(/\b(\d{4})-(\d{2})-(\d{2})\b/);

  if (isoDateMatch) {
    year = Number(isoDateMatch[1]);
    month = Number(isoDateMatch[2]);
    day = Number(isoDateMatch[3]);
  } else {
    const englishDateMatch = rawValue.match(
      /\b(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat)\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{4})\b/i
    );

    if (englishDateMatch) {
      const monthNumbers = {
        jan: 1,
        feb: 2,
        mar: 3,
        apr: 4,
        may: 5,
        jun: 6,
        jul: 7,
        aug: 8,
        sep: 9,
        oct: 10,
        nov: 11,
        dec: 12
      };

      month = monthNumbers[englishDateMatch[1].toLowerCase()];
      day = Number(englishDateMatch[2]);
      year = Number(englishDateMatch[3]);
    }
  }

  const timeMatches = [...rawValue.matchAll(/\b([01]?\d|2[0-3]):([0-5]\d)\b/g)];
  const lastTimeMatch = timeMatches.length
    ? timeMatches[timeMatches.length - 1]
    : null;

  let formattedTime = "Hora no disponible";

  if (lastTimeMatch) {
    const hours24 = Number(lastTimeMatch[1]);
    const minutes = lastTimeMatch[2];
    const period = hours24 >= 12 ? "p. m." : "a. m.";
    const hours12 = hours24 % 12 || 12;

    formattedTime = `${hours12}:${minutes} ${period}`;
  }

  let formattedDate = "Fecha no disponible";

  if (
    Number.isInteger(year) &&
    Number.isInteger(month) &&
    Number.isInteger(day) &&
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= 31
  ) {
    const monthNames = [
      "enero",
      "febrero",
      "marzo",
      "abril",
      "mayo",
      "junio",
      "julio",
      "agosto",
      "septiembre",
      "octubre",
      "noviembre",
      "diciembre"
    ];

    const weekdayNames = [
      "domingo",
      "lunes",
      "martes",
      "miércoles",
      "jueves",
      "viernes",
      "sábado"
    ];

    const weekdayIndex = new Date(
      Date.UTC(year, month - 1, day, 12)
    ).getUTCDay();

    formattedDate =
      `${weekdayNames[weekdayIndex]}, ${day} de ` +
      `${monthNames[month - 1]} de ${year}`;
  }

  return {
    date: formattedDate,
    time: formattedTime,
    full: `${formattedDate} • ${formattedTime}`
  };
}


  async function sendTicketEmail(ticket) {
  if (!resend) {
    console.warn("Resend no está configurado.");
    return;
  }

  const customerEmail = ticket?.customer?.email;

  if (!customerEmail) {
    console.warn("El boleto no tiene correo del cliente.");
    return;
  }

  const qrBuffer = await QRCode.toBuffer(String(ticket.qr || ""), {
  type: "png",
  width: 320,
  margin: 2
});

const qrFilePath = `tickets/${ticket.id}-qr.png`;
const { error: qrUploadError } = await supabase.storage
  .from(SUPABASE_POSTERS_BUCKET)
  .upload(qrFilePath, qrBuffer, {
    contentType: "image/png",
    cacheControl: "31536000",
    upsert: true
  });

if (qrUploadError) {
  throw new Error(qrUploadError.message);
}

const { data: qrPublicData } = supabase.storage
  .from(SUPABASE_POSTERS_BUCKET)
  .getPublicUrl(qrFilePath);

const qrPublicUrl = qrPublicData.publicUrl;

  const seats = Array.isArray(ticket.seats)
    ? ticket.seats.join(", ")
    : String(ticket.seats || "");

  const ticketDateTime = formatTicketDateTime(ticket.time);

  const { error } = await resend.emails.send({
    from: RESEND_FROM_EMAIL,
    to: [customerEmail],
    subject: `Tu boleto para ${ticket.movie}`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:24px;background:#0f172a;color:#ffffff;border-radius:16px;">
        <h1 style="margin-top:0;">🎟️ Boleto confirmado</h1>
        <p>Tu pago fue confirmado correctamente.</p>

        <h2>${ticket.movie}</h2>

        <div style="margin:20px 0;padding:16px 18px;background:#111827;border:1px solid #334155;border-radius:12px;">
          <p style="margin:0 0 8px;color:#cbd5e1;font-size:14px;font-weight:700;">
            Fecha y hora
          </p>
          <p style="margin:0 0 6px;font-size:17px;font-weight:800;color:#ffffff;">
            📅 ${ticketDateTime.date}
          </p>
          <p style="margin:0;font-size:17px;font-weight:800;color:#ffffff;">
            🕔 ${ticketDateTime.time}
          </p>
        </div>
        <p><strong>Asientos:</strong> ${seats}</p>
        <p><strong>Total:</strong> $${Number(ticket.total).toFixed(2)}</p>
        <p><strong>Código manual:</strong> ${ticket.manualCode}</p>
        <p><strong>Reservación:</strong> ${ticket.id}</p>

        <div style="margin-top:24px;text-align:center;">
          <img
  src="${qrPublicUrl}"
  alt="Código QR del boleto"
  width="260"
  style="display:block;margin:0 auto;background:#ffffff;padding:12px;border-radius:12px;"
/>
        </div>

        <p style="margin-top:24px;color:#cbd5e1;">
          Presenta este código QR al entrar al cine.
        </p>
      </div>
    `,

  });

  if (error) {
    throw new Error(error.message || "No se pudo enviar el boleto.");
  }
}

function formatMovie(row) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    posterUrl: row.poster_url,
    trailerUrl: row.trailer_url,
    durationMinutes: row.duration_minutes,
    rating: row.rating,
    active: row.active,
    comingSoon: Boolean(row.coming_soon),
    created: row.created_at
  };
}

const SHOWTIME_LANGUAGES = {
  spanish: "Español",
  english: "Ingles",
  english_subtitled: "Ingles con subtitulos en español"
};

function normalizeShowtimeLanguage(value) {
  const language = String(value || "spanish").trim();
  return Object.prototype.hasOwnProperty.call(SHOWTIME_LANGUAGES, language)
    ? language
    : null;
}

function formatShowtime(row) {
  const language = normalizeShowtimeLanguage(row.language) || "spanish";

  return {
    id: row.id,
    movieId: row.movie_id,
    movieTitle: row.movie_title,
    showDate: row.show_date,
    showTime: row.show_time,
    price: Number(row.global_adult_price ?? row.adult_price ?? row.price),
    adultPrice: Number(row.global_adult_price ?? row.adult_price ?? row.price),
    childPrice: Number(row.global_child_price ?? row.child_price ?? row.price),
    seniorPrice: Number(row.global_senior_price ?? row.senior_price ?? row.price),
    language,
    languageLabel: SHOWTIME_LANGUAGES[language],
    active: row.active,
    created: row.created_at
  };
}

function formatEmployee(row) {
  return {
    id: row.id, name: row.name, username: row.username, active: row.active,
    created: row.created_at, scans: Number(row.scans || 0),
    ticketsScanned: Number(row.tickets_scanned || 0), lastScan: row.last_scan || null
  };
}

function formatCheckin(row) {
  return {
    id: row.id, ticketId: row.ticket_id, employeeId: row.employee_id,
    employeeName: row.employee_name, employeeUsername: row.employee_username,
    seatsCount: Number(row.seats_count || 0), movie: row.movie,
    showTime: row.show_time, seats: row.seats || [], scannedAt: row.scanned_at
  };
}

/*
==================================================
CREAR TABLAS AUTOMÃTICAMENTE
==================================================
*/

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tickets (
      id UUID PRIMARY KEY,
      movie TEXT NOT NULL,
      show_time TEXT NOT NULL,
      seats TEXT[] NOT NULL,
      total NUMERIC(10, 2) NOT NULL,
      customer JSONB NOT NULL,
      payment_status TEXT NOT NULL DEFAULT 'pending',
      qr TEXT UNIQUE NOT NULL,
      manual_code VARCHAR(5) UNIQUE,
      used BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      checkin_at TIMESTAMPTZ
    );
  `);

  await pool.query(`
    ALTER TABLE tickets
    ADD COLUMN IF NOT EXISTS manual_code VARCHAR(5);
  `);

await pool.query(`
  ALTER TABLE tickets
  DROP CONSTRAINT IF EXISTS tickets_manual_code_format_check;
`);

await pool.query(`
  ALTER TABLE tickets
  ADD CONSTRAINT tickets_manual_code_format_check
  CHECK (
    manual_code IS NULL
    OR manual_code ~ '^[0-9]{5}$'
  );
`);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS tickets_manual_code_unique_idx
    ON tickets (manual_code)
    WHERE manual_code IS NOT NULL;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS movies (
      id UUID PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      poster_url TEXT,
      trailer_url TEXT,
      duration_minutes INTEGER,
      rating TEXT,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
  ALTER TABLE movies
  ADD COLUMN IF NOT EXISTS trailer_url TEXT;
`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS showtimes (
      id UUID PRIMARY KEY,
      movie_id UUID NOT NULL
        REFERENCES movies(id)
        ON DELETE CASCADE,
      show_date DATE NOT NULL,
      show_time TEXT NOT NULL,
      price NUMERIC(10, 2) NOT NULL,
      adult_price NUMERIC(10, 2),
      child_price NUMERIC(10, 2),
      senior_price NUMERIC(10, 2),
      language TEXT NOT NULL DEFAULT 'spanish',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    ALTER TABLE showtimes
    ADD COLUMN IF NOT EXISTS language TEXT NOT NULL DEFAULT 'spanish';
  `);

  await pool.query(`
    ALTER TABLE showtimes
      ADD COLUMN IF NOT EXISTS adult_price NUMERIC(10, 2),
      ADD COLUMN IF NOT EXISTS child_price NUMERIC(10, 2),
      ADD COLUMN IF NOT EXISTS senior_price NUMERIC(10, 2);
  `);

  await pool.query(`
    UPDATE showtimes
    SET
      adult_price = COALESCE(adult_price, price),
      child_price = COALESCE(child_price, price),
      senior_price = COALESCE(senior_price, price);
  `);

  await pool.query(`
    ALTER TABLE tickets
    ADD COLUMN IF NOT EXISTS ticket_breakdown JSONB;
  `);

  await pool.query(`
    UPDATE showtimes
    SET language = 'spanish'
    WHERE language IS NULL
       OR language NOT IN ('spanish', 'english', 'english_subtitled');
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS employees (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS employees_username_lower_unique ON employees (LOWER(username));`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS employee_sessions (
      id UUID PRIMARY KEY,
      employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
      token_hash TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS employee_sessions_expires_at_idx ON employee_sessions (expires_at);`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS checkins (
      id UUID PRIMARY KEY,
      ticket_id UUID UNIQUE NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
      employee_id UUID REFERENCES employees(id) ON DELETE SET NULL,
      employee_name TEXT NOT NULL,
      employee_username TEXT NOT NULL,
      seats_count INTEGER NOT NULL CHECK (seats_count > 0),
      movie TEXT NOT NULL,
      show_time TEXT NOT NULL,
      seats TEXT[] NOT NULL,
      scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS checkins_employee_id_idx ON checkins (employee_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS checkins_scanned_at_idx ON checkins (scanned_at DESC);`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_password_resets (
      id UUID PRIMARY KEY,
      email TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS admin_password_resets_email_idx
    ON admin_password_resets (email, created_at DESC);
  `);

  await pool.query(`
    DELETE FROM admin_password_resets
    WHERE
      used_at IS NOT NULL
      OR expires_at < NOW() - INTERVAL '1 day';
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ticket_prices (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      adult_price NUMERIC(10, 2) NOT NULL CHECK (adult_price >= 0),
      child_price NUMERIC(10, 2) NOT NULL CHECK (child_price >= 0),
      senior_price NUMERIC(10, 2) NOT NULL CHECK (senior_price >= 0),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    INSERT INTO ticket_prices (id, adult_price, child_price, senior_price)
    VALUES (1, 8.25, 6.00, 6.00)
    ON CONFLICT (id) DO NOTHING;
  `);

  const adminResult = await pool.query(`
    SELECT id
    FROM admin_settings
    WHERE id = 1;
  `);

  if (adminResult.rowCount === 0) {
    const initialCredentials =
      await hashPassword(INITIAL_ADMIN_PASSWORD);

    await pool.query(
      `
        INSERT INTO admin_settings (
          id,
          password_salt,
          password_hash
        )
        VALUES (1, $1, $2);
      `,
      [
        initialCredentials.salt,
        initialCredentials.hash
      ]
    );

    console.log("ContraseÃ±a administrativa inicial creada.");
  }

  console.log("Base de datos preparada correctamente.");
}

/*
==================================================
REINICIO DIARIO A LAS 3:00 A. M.
HORA DE PUERTO RICO
==================================================

Solo elimina reservaciones y taquillas.
No elimina pelÃ­culas, tandas ni contraseÃ±a.
*/

async function cleanupPreviousBusinessDay() {
  const expiredSessions = await pool.query(`
    DELETE FROM employee_sessions
    WHERE expires_at <= NOW();
  `);

  const pendingTickets = await pool.query(
    `
      DELETE FROM tickets
      WHERE payment_status = 'pending'
        AND created_at < NOW() - ($1 * INTERVAL '1 minute');
    `,
    [PENDING_RESERVATION_MINUTES]
  );

  const oldResetCodes = await pool.query(
    `
      DELETE FROM admin_password_resets
      WHERE
        used_at IS NOT NULL
        OR expires_at < NOW() - ($1 * INTERVAL '1 day');
    `,
    [PASSWORD_RESET_RETENTION_DAYS]
  );

  let deletedQrFiles = 0;

  try {
    deletedQrFiles = await cleanupOldQrFiles();
  } catch (error) {
    console.error(
      "No se pudieron limpiar QR antiguos de Supabase:",
      error
    );
  }

  if (
    expiredSessions.rowCount > 0 ||
    pendingTickets.rowCount > 0 ||
    oldResetCodes.rowCount > 0 ||
    deletedQrFiles > 0
  ) {
    console.log("Limpieza automática completada:", {
      employeeSessions: expiredSessions.rowCount,
      pendingReservations: pendingTickets.rowCount,
      passwordResetCodes: oldResetCodes.rowCount,
      qrFiles: deletedQrFiles
    });
  }
}

let lastCleanupCheck = 0;

app.use(async (req, res, next) => {
  const now = Date.now();

  if (now - lastCleanupCheck < CLEANUP_INTERVAL_MS) {
    return next();
  }

  lastCleanupCheck = now;

  try {
    await cleanupPreviousBusinessDay();
  } catch (error) {
    console.error("Error realizando el reinicio diario:", error);
  }

  next();
});

/*
==================================================
ESTADO DEL SERVIDOR
==================================================
*/

app.get("/", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "online",
      database: "connected",
      dailyReset: "3:00 AM America/Puerto_Rico",
      app: "Cine Teatro Manuel Nieves Quintero",
      version: "5.0"
    });
  } catch (error) {
    console.error("Error verificando la base de datos:", error);

    res.status(500).json({
      status: "error",
      database: "disconnected"
    });
  }
});

/*
==================================================
CARTELERA PÃBLICA
==================================================
*/

app.get("/api/movies", async (req, res) => {
  try {
    const movieResult = await pool.query(`
      SELECT *
      FROM movies
      WHERE active = TRUE
      ORDER BY created_at DESC;
    `);

    const showtimeResult = await pool.query(`
      SELECT
        s.*,
        m.title AS movie_title,
        tp.adult_price AS global_adult_price,
        tp.child_price AS global_child_price,
        tp.senior_price AS global_senior_price
      FROM showtimes s
      JOIN movies m ON m.id = s.movie_id
      CROSS JOIN ticket_prices tp
      WHERE
        s.active = TRUE
        AND m.active = TRUE
        AND s.show_date >=
          (NOW() AT TIME ZONE 'America/Puerto_Rico')::date
      ORDER BY s.show_date ASC, s.show_time ASC;
    `);

    const showtimes = showtimeResult.rows.map(formatShowtime);

    const movies = movieResult.rows.map((row) => {
      const movie = formatMovie(row);

      return {
        ...movie,
        showtimes: showtimes.filter(
          (showtime) => showtime.movieId === movie.id
        )
      };
    });

    res.json(movies);
  } catch (error) {
    console.error("Error obteniendo la cartelera:", error);

    res.status(500).json({
      error: "No se pudo obtener la cartelera."
    });
  }
});

/*
==================================================
PRECIOS GENERALES DE TAQUILLAS
==================================================
*/

app.get("/api/ticket-prices", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT adult_price, child_price, senior_price
      FROM ticket_prices
      WHERE id = 1;
    `);
    const row = result.rows[0];
    res.json({
      adultPrice: Number(row.adult_price),
      childPrice: Number(row.child_price),
      seniorPrice: Number(row.senior_price)
    });
  } catch (error) {
    console.error("Error obteniendo precios generales:", error);
    res.status(500).json({ error: "No se pudieron obtener los precios." });
  }
});

app.get("/api/admin/ticket-prices", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT adult_price, child_price, senior_price
      FROM ticket_prices
      WHERE id = 1;
    `);
    const row = result.rows[0];
    res.json({
      adultPrice: Number(row.adult_price),
      childPrice: Number(row.child_price),
      seniorPrice: Number(row.senior_price)
    });
  } catch (error) {
    console.error("Error obteniendo precios para administrador:", error);
    res.status(500).json({ error: "No se pudieron obtener los precios." });
  }
});

app.put("/api/admin/ticket-prices", requireAdmin, async (req, res) => {
  try {
    const adultPrice = Number(req.body.adultPrice);
    const childPrice = Number(req.body.childPrice);
    const seniorPrice = Number(req.body.seniorPrice);

    if (
      !Number.isFinite(adultPrice) ||
      !Number.isFinite(childPrice) ||
      !Number.isFinite(seniorPrice) ||
      adultPrice < 0 ||
      childPrice < 0 ||
      seniorPrice < 0
    ) {
      return res.status(400).json({
        error: "Los precios de adulto, niÃ±o y senior deben ser vÃ¡lidos."
      });
    }

    const result = await pool.query(
      `
        UPDATE ticket_prices
        SET adult_price = $1, child_price = $2, senior_price = $3, updated_at = NOW()
        WHERE id = 1
        RETURNING adult_price, child_price, senior_price;
      `,
      [adultPrice, childPrice, seniorPrice]
    );

    const row = result.rows[0];
    res.json({
      success: true,
      adultPrice: Number(row.adult_price),
      childPrice: Number(row.child_price),
      seniorPrice: Number(row.senior_price)
    });
  } catch (error) {
    console.error("Error actualizando precios generales:", error);
    res.status(500).json({ error: "No se pudieron actualizar los precios." });
  }
});

/*
==================================================
AUTENTICACIÃN DEL ADMINISTRADOR
==================================================
*/


app.post("/api/admin/password/forgot", async (req, res) => {
  try {
    if (!ADMIN_RECOVERY_EMAIL) {
      return res.status(503).json({
        error:
          "La recuperación de contraseña todavía no está configurada."
      });
    }

    if (!resend) {
      return res.status(503).json({
        error:
          "El servicio de correo todavía no está configurado."
      });
    }

    const email = normalizeRecoveryEmail(req.body?.email);

    if (!email) {
      return res.status(400).json({
        error: "Escribe el correo del administrador."
      });
    }

    // Respuesta genérica para no revelar públicamente cuál es
    // el correo autorizado del administrador.
    if (email !== ADMIN_RECOVERY_EMAIL) {
      return res.json({
        success: true,
        message:
          "Si el correo coincide con el administrador, recibirás un código."
      });
    }

    // Evita generar códigos uno detrás de otro.
    const recentResult = await pool.query(
      `
        SELECT created_at
        FROM admin_password_resets
        WHERE
          email = $1
          AND created_at > NOW() - INTERVAL '60 seconds'
        ORDER BY created_at DESC
        LIMIT 1;
      `,
      [email]
    );

    if (recentResult.rowCount > 0) {
      return res.status(429).json({
        error:
          "Espera un minuto antes de solicitar otro código."
      });
    }

    const code = String(
      crypto.randomInt(0, 1000000)
    ).padStart(6, "0");

    const resetId = crypto.randomUUID();
    const codeHash = hashAdminRecoveryCode(email, code);

    await pool.query(
      `
        UPDATE admin_password_resets
        SET used_at = NOW()
        WHERE
          email = $1
          AND used_at IS NULL;
      `,
      [email]
    );

    await pool.query(
      `
        INSERT INTO admin_password_resets (
          id,
          email,
          code_hash,
          expires_at
        )
        VALUES (
          $1,
          $2,
          $3,
          NOW() + ($4 * INTERVAL '1 minute')
        );
      `,
      [
        resetId,
        email,
        codeHash,
        ADMIN_RECOVERY_CODE_MINUTES
      ]
    );

    try {
      await sendAdminRecoveryEmail(code);
    } catch (emailError) {
      await pool.query(
        `
          UPDATE admin_password_resets
          SET used_at = NOW()
          WHERE id = $1;
        `,
        [resetId]
      );

      throw emailError;
    }

    res.json({
      success: true,
      message:
        "Si el correo coincide con el administrador, recibirás un código."
    });
  } catch (error) {
    console.error(
      "Error solicitando recuperación administrativa:",
      error
    );

    res.status(500).json({
      error:
        error.message ||
        "No se pudo enviar el código de recuperación."
    });
  }
});

app.post("/api/admin/password/reset", async (req, res) => {
  const client = await pool.connect();

  try {
    const email = normalizeRecoveryEmail(req.body?.email);
    const code = String(req.body?.code || "").trim();
    const newPassword = String(
      req.body?.newPassword || ""
    );

    if (
      !email ||
      !/^\d{6}$/.test(code) ||
      newPassword.length < 8
    ) {
      return res.status(400).json({
        error:
          "Revisa el correo, el código y la nueva contraseña."
      });
    }

    if (
      !ADMIN_RECOVERY_EMAIL ||
      email !== ADMIN_RECOVERY_EMAIL
    ) {
      return res.status(400).json({
        error:
          "El código es inválido o ya venció."
      });
    }

    await client.query("BEGIN");

    const resetResult = await client.query(
      `
        SELECT
          id,
          code_hash,
          attempts,
          expires_at,
          used_at
        FROM admin_password_resets
        WHERE email = $1
        ORDER BY created_at DESC
        LIMIT 1
        FOR UPDATE;
      `,
      [email]
    );

    const reset = resetResult.rows[0];

    if (
      !reset ||
      reset.used_at ||
      new Date(reset.expires_at).getTime() <= Date.now() ||
      Number(reset.attempts || 0) >= ADMIN_RECOVERY_MAX_ATTEMPTS
    ) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error:
          "El código es inválido o ya venció. Solicita uno nuevo."
      });
    }

    const providedHash =
      hashAdminRecoveryCode(email, code);

    const validCode = safeEqualHex(
      providedHash,
      reset.code_hash
    );

    if (!validCode) {
      await client.query(
        `
          UPDATE admin_password_resets
          SET attempts = attempts + 1
          WHERE id = $1;
        `,
        [reset.id]
      );

      await client.query("COMMIT");

      return res.status(400).json({
        error: "El código de recuperación es incorrecto."
      });
    }

    const newCredentials =
      await hashPassword(newPassword);

    await client.query(
      `
        UPDATE admin_settings
        SET
          password_salt = $1,
          password_hash = $2,
          updated_at = NOW()
        WHERE id = 1;
      `,
      [
        newCredentials.salt,
        newCredentials.hash
      ]
    );

    await client.query(
      `
        UPDATE admin_password_resets
        SET used_at = NOW()
        WHERE email = $1
          AND used_at IS NULL;
      `,
      [email]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Contraseña actualizada correctamente."
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});

    console.error(
      "Error restableciendo contraseña administrativa:",
      error
    );

    res.status(500).json({
      error:
        "No se pudo restablecer la contraseña."
    });
  } finally {
    client.release();
  }
});

app.post("/api/admin/login", async (req, res) => {
  try {
    const { password } = req.body;

    const valid = await isValidAdminPassword(password);

    if (!valid) {
      return res.status(401).json({
        error: "Contraseña incorrecta."
      });
    }

    res.json({
      success: true,
      message: "Acceso autorizado."
    });
  } catch (error) {
    console.error("Error iniciando sesiÃ3n:", error);

    res.status(500).json({
      error: "No se pudo iniciar sesiÃ3n."
    });
  }
});

app.put(
  "/api/admin/password",
  requireAdmin,
  async (req, res) => {
    try {
      const {
        currentPassword,
        newPassword
      } = req.body;

      const currentPasswordValid =
        await isValidAdminPassword(currentPassword);

      if (!currentPasswordValid) {
        return res.status(401).json({
          error: "La contraseña actual es incorrecta."
        });
      }

      if (
        typeof newPassword !== "string" ||
        newPassword.length < 8
      ) {
        return res.status(400).json({
          error:
            "La nueva contraseña debe tener al menos 8 caracteres."
        });
      }

      if (newPassword === currentPassword) {
        return res.status(400).json({
          error:
            "La nueva contraseña debe ser diferente a la actual."
        });
      }

      const credentials = await hashPassword(newPassword);

      await pool.query(
        `
          UPDATE admin_settings
          SET
            password_salt = $1,
            password_hash = $2,
            updated_at = NOW()
          WHERE id = 1;
        `,
        [
          credentials.salt,
          credentials.hash
        ]
      );

      res.json({
        success: true,
        message: "Contraseña actualizada correctamente."
      });
    } catch (error) {
      console.error(
        "Error cambiando la contraseÃ±a:",
        error
      );

      res.status(500).json({
        error: "No se pudo cambiar la contraseÃ±a."
      });
    }
  }
);


/*
==================================================
CUENTAS Y SESIONES DE EMPLEADOS
==================================================
*/

app.post("/api/employee/login", async (req, res) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const password = req.body?.password;
    if (!username || typeof password !== "string") {
      return res.status(400).json({ error: "Escribe el usuario y la contraseÃ±a." });
    }
    const result = await pool.query(`SELECT * FROM employees WHERE LOWER(username) = $1;`, [username]);
    if (result.rowCount === 0) return res.status(401).json({ error: "Usuario o contraseÃ±a incorrectos." });
    const employee = result.rows[0];
    if (!employee.active) return res.status(403).json({ error: "Esta cuenta estÃ¡ desactivada." });
    const valid = await verifyPassword(password, employee.password_salt, employee.password_hash);
    if (!valid) return res.status(401).json({ error: "Usuario o contraseÃ±a incorrectos." });
    const token = crypto.randomBytes(32).toString("hex");
    await pool.query(`INSERT INTO employee_sessions (id, employee_id, token_hash, expires_at) VALUES ($1,$2,$3,NOW()+INTERVAL '12 hours');`, [crypto.randomUUID(), employee.id, hashSessionToken(token)]);
    res.json({ success: true, token, expiresInHours: 12, employee: { id: employee.id, name: employee.name, username: employee.username } });
  } catch (error) {
    console.error("Error iniciando sesiÃ3n de empleado:", error);
    res.status(500).json({ error: "No se pudo iniciar la sesiÃ3n." });
  }
});

app.get("/api/employee/me", requireEmployee, async (req, res) => {
  res.json({ employee: { id: req.employee.id, name: req.employee.name, username: req.employee.username } });
});

app.get("/api/employee/session-summary", requireEmployee, async (req, res) => {
  try {
    const sessionStartedAt = req.employee.session_created_at;

    const summaryResult = await pool.query(
      `
        SELECT
          COUNT(*)::int AS scans,
          COALESCE(SUM(seats_count), 0)::int AS tickets_scanned,
          MAX(scanned_at) AS last_scan
        FROM checkins
        WHERE
          employee_id = $1
          AND scanned_at >= $2;
      `,
      [req.employee.id, sessionStartedAt]
    );

    const historyResult = await pool.query(
      `
        SELECT *
        FROM checkins
        WHERE
          employee_id = $1
          AND scanned_at >= $2
        ORDER BY scanned_at DESC
        LIMIT 8;
      `,
      [req.employee.id, sessionStartedAt]
    );

    const summary = summaryResult.rows[0] || {};

    res.json({
      success: true,
      sessionStartedAt,
      sessionExpiresAt: req.employee.session_expires_at,
      employee: {
        id: req.employee.id,
        name: req.employee.name,
        username: req.employee.username
      },
      scans: Number(summary.scans || 0),
      ticketsScanned: Number(summary.tickets_scanned || 0),
      lastScan: summary.last_scan || null,
      history: historyResult.rows.map(formatCheckin)
    });
  } catch (error) {
    console.error("Error obteniendo resumen de sesión del empleado:", error);
    res.status(500).json({
      error: "No se pudo obtener el resumen de la sesión."
    });
  }
});

app.post("/api/employee/logout", requireEmployee, async (req, res) => {
  try {
    await pool.query(`DELETE FROM employee_sessions WHERE token_hash = $1;`, [req.employeeTokenHash]);
    res.json({ success: true, message: "SesiÃ3n cerrada correctamente." });
  } catch (error) {
    console.error("Error cerrando sesiÃ3n de empleado:", error);
    res.status(500).json({ error: "No se pudo cerrar la sesiÃ3n." });
  }
});

/*
==================================================
ADMINISTRACIÃN DE EMPLEADOS
==================================================
*/

app.get("/api/admin/employees", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT e.*, COUNT(c.id) AS scans, COALESCE(SUM(c.seats_count),0) AS tickets_scanned, MAX(c.scanned_at) AS last_scan
      FROM employees e LEFT JOIN checkins c ON c.employee_id = e.id
      GROUP BY e.id ORDER BY e.name ASC;
    `);
    res.json(result.rows.map(formatEmployee));
  } catch (error) {
    console.error("Error obteniendo empleados:", error);
    res.status(500).json({ error: "No se pudieron obtener los empleados." });
  }
});

app.post("/api/admin/employees", requireAdmin, async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const username = normalizeUsername(req.body?.username);
    const password = req.body?.password;
    const active = req.body?.active !== false;
    if (!name) return res.status(400).json({ error: "El nombre del empleado es obligatorio." });
    if (!/^[a-z0-9._-]{3,30}$/.test(username)) return res.status(400).json({ error: "El usuario debe tener entre 3 y 30 caracteres y solo puede usar letras, nÃomeros, punto, guion o guion bajo." });
    if (typeof password !== "string" || password.length < 8) return res.status(400).json({ error: "La contraseÃ±a debe tener al menos 8 caracteres." });
    const credentials = await hashPassword(password);
    const result = await pool.query(`INSERT INTO employees (id,name,username,password_salt,password_hash,active) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *;`, [crypto.randomUUID(),name,username,credentials.salt,credentials.hash,Boolean(active)]);
    res.status(201).json(formatEmployee(result.rows[0]));
  } catch (error) {
    if (error?.code === "23505") return res.status(409).json({ error: "Ese nombre de usuario ya estÃ¡ registrado." });
    console.error("Error creando empleado:", error);
    res.status(500).json({ error: "No se pudo crear el empleado." });
  }
});

app.put("/api/admin/employees/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const name = String(req.body?.name || "").trim();
    const username = normalizeUsername(req.body?.username);
    const password = req.body?.password;
    const active = req.body?.active !== false;
    if (!name) return res.status(400).json({ error: "El nombre del empleado es obligatorio." });
    if (!/^[a-z0-9._-]{3,30}$/.test(username)) return res.status(400).json({ error: "El nombre de usuario no es vÃ¡lido." });
    let result;
    if (typeof password === "string" && password.length > 0) {
      if (password.length < 8) return res.status(400).json({ error: "La contraseÃ±a debe tener al menos 8 caracteres." });
      const credentials = await hashPassword(password);
      result = await pool.query(`UPDATE employees SET name=$1,username=$2,password_salt=$3,password_hash=$4,active=$5,updated_at=NOW() WHERE id=$6 RETURNING *;`, [name,username,credentials.salt,credentials.hash,Boolean(active),id]);
      await pool.query(`DELETE FROM employee_sessions WHERE employee_id = $1;`, [id]);
    } else {
      result = await pool.query(`UPDATE employees SET name=$1,username=$2,active=$3,updated_at=NOW() WHERE id=$4 RETURNING *;`, [name,username,Boolean(active),id]);
      if (!active) await pool.query(`DELETE FROM employee_sessions WHERE employee_id = $1;`, [id]);
    }
    if (result.rowCount === 0) return res.status(404).json({ error: "Empleado no encontrado." });
    res.json(formatEmployee(result.rows[0]));
  } catch (error) {
    if (error?.code === "23505") return res.status(409).json({ error: "Ese nombre de usuario ya estÃ¡ registrado." });
    console.error("Error actualizando empleado:", error);
    res.status(500).json({ error: "No se pudo actualizar el empleado." });
  }
});

app.delete("/api/admin/employees/:id", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`DELETE FROM employees WHERE id=$1 RETURNING id;`, [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: "Empleado no encontrado." });
    res.json({ success: true, message: "Empleado eliminado. Su historial de escaneos se conserva." });
  } catch (error) {
    console.error("Error eliminando empleado:", error);
    res.status(500).json({ error: "No se pudo eliminar el empleado." });
  }
});

app.get("/api/admin/checkins", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit)||200,1),1000);
    const result = await pool.query(`SELECT * FROM checkins ORDER BY scanned_at DESC LIMIT $1;`, [limit]);
    res.json(result.rows.map(formatCheckin));
  } catch (error) {
    console.error("Error obteniendo historial de escaneos:", error);
    res.status(500).json({ error: "No se pudo obtener el historial de escaneos." });
  }
});

/*
==================================================
SUBIR AFICHE A SUPABASE STORAGE
==================================================
*/

app.post(
  "/api/admin/posters",
  requireAdmin,
  posterUpload.single("poster"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: "Selecciona una imagen para el afiche."
        });
      }

      const extension =
        extensionFromMimeType(req.file.mimetype);

      const fileName =
        `${Date.now()}-${crypto.randomUUID()}.${extension}`;

      const filePath = `movies/${fileName}`;

      const { error: uploadError } =
        await supabase.storage
          .from(SUPABASE_POSTERS_BUCKET)
          .upload(
            filePath,
            req.file.buffer,
            {
              contentType: req.file.mimetype,
              cacheControl: "31536000",
              upsert: false
            }
          );

      if (uploadError) {
        console.error(
          "Error de Supabase subiendo afiche:",
          uploadError
        );

        return res.status(502).json({
          error:
            "No se pudo subir el afiche a Supabase Storage."
        });
      }

      const { data: publicUrlData } =
        supabase.storage
          .from(SUPABASE_POSTERS_BUCKET)
          .getPublicUrl(filePath);

      if (!publicUrlData?.publicUrl) {
        return res.status(500).json({
          error:
            "El afiche se subiÃ3, pero no se pudo obtener su URL pÃoblica."
        });
      }

      res.status(201).json({
        success: true,
        posterUrl: publicUrlData.publicUrl,
        path: filePath
      });
    } catch (error) {
      console.error("Error subiendo afiche:", error);

      res.status(500).json({
        error: "No se pudo subir el afiche."
      });
    }
  }
);

/*
==================================================
ADMINISTRACIÃN DE PELÃCULAS
==================================================
*/

app.get(
  "/api/admin/movies",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT *
        FROM movies
        ORDER BY created_at DESC;
      `);

      res.json(result.rows.map(formatMovie));
    } catch (error) {
      console.error(
        "Error obteniendo pelÃ­culas:",
        error
      );

      res.status(500).json({
        error: "No se pudieron obtener las pelÃ­culas."
      });
    }
  }
);

app.post(
  "/api/admin/movies",
  requireAdmin,
  async (req, res) => {
    try {
      const {
        title,
        description = "",
        posterUrl = "",
        trailerUrl = "",
        durationMinutes = null,
        rating = "",
        active = true, 
        comingSoon = false
      } = req.body;

      if (
        typeof title !== "string" ||
        !title.trim()
      ) {
        return res.status(400).json({
          error: "El tÃ­tulo de la pelÃ­cula es obligatorio."
        });
      }

      if (
        durationMinutes !== null &&
        (
          !Number.isInteger(Number(durationMinutes)) ||
          Number(durationMinutes) <= 0
        )
      ) {
        return res.status(400).json({
          error:
            "La duraciÃ3n debe ser un nÃomero entero mayor que cero."
        });
      }

      const id = crypto.randomUUID();

      const result = await pool.query(
        `
          INSERT INTO movies (
            id,
            title,
            description,
            poster_url,
            trailer_url,
            duration_minutes,
            rating,
            active
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          RETURNING *;
        `,
        [
          id,
          title.trim(),
          description.trim(),
          posterUrl.trim(),
          trailerUrl.trim(),
          durationMinutes === null
            ? null
            : Number(durationMinutes),
          rating.trim(),
          Boolean(active)
        ]
      );

      res.status(201).json(
        formatMovie(result.rows[0])
      );
    } catch (error) {
      console.error(
        "Error creando pelÃ­cula:",
        error
      );

      res.status(500).json({
        error: "No se pudo crear la pelÃ­cula."
      });
    }
  }
);

app.put(
  "/api/admin/movies/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const {
        title,
        description = "",
        posterUrl = "",
        trailerUrl = "",
        durationMinutes = null,
        rating = "",
        active = true,
        comingSoon = false 
      } = req.body;

      if (
        typeof title !== "string" ||
        !title.trim()
      ) {
        return res.status(400).json({
          error: "El tÃ­tulo de la pelÃ­cula es obligatorio."
        });
      }

      if (
        durationMinutes !== null &&
        (
          !Number.isInteger(Number(durationMinutes)) ||
          Number(durationMinutes) <= 0
        )
      ) {
        return res.status(400).json({
          error:
            "La duraciÃ3n debe ser un nÃomero entero mayor que cero."
        });
      }

      const result = await pool.query(
        `
          UPDATE movies
          SET
            title = $1,
            description = $2,
            poster_url = $3,
            trailer_url = $4,
            duration_minutes = $5,
            rating = $6,
            active = $7,
            coming_soon = $8
          WHERE id = $9
          RETURNING *;
        `,
        [
          title.trim(),
          description.trim(),
          posterUrl.trim(),
          trailerUrl.trim(),
          durationMinutes === null
            ? null
            : Number(durationMinutes),
          rating.trim(),
          Boolean(active),
          Boolean(comingSoon),
          id
        ]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "PelÃ­cula no encontrada."
        });
      }

      res.json(formatMovie(result.rows[0]));
    } catch (error) {
      console.error(
        "Error actualizando pelÃ­cula:",
        error
      );

      res.status(500).json({
        error: "No se pudo actualizar la pelÃ­cula."
      });
    }
  }
);

app.delete(
  "/api/admin/movies/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const movieResult = await pool.query(
        `
          SELECT id, poster_url, trailer_url
          FROM movies
          WHERE id = $1;
        `,
        [id]
      );

      if (movieResult.rowCount === 0) {
        return res.status(404).json({
          error: "Película no encontrada."
        });
      }

      const movie = movieResult.rows[0];

      const deleteResult = await pool.query(
        `
          DELETE FROM movies
          WHERE id = $1
          RETURNING id;
        `,
        [id]
      );

      if (deleteResult.rowCount === 0) {
        return res.status(404).json({
          error: "Película no encontrada."
        });
      }

      try {
        await deleteMovieStorageFiles(movie);
      } catch (storageError) {
        console.error(
          "La película se eliminó de la base de datos, pero no se pudieron borrar todos sus archivos de Supabase:",
          storageError
        );
      }

      res.json({
        success: true,
        message:
          "Película eliminada correctamente. Sus archivos asociados también se limpiaron cuando fue posible."
      });
    } catch (error) {
      console.error("Error eliminando película:", error);

      res.status(500).json({
        error: "No se pudo eliminar la película."
      });
    }
  }
);

/*
==================================================
ADMINISTRACIÃN DE TANDAS
==================================================
*/

app.get(
  "/api/admin/showtimes",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          s.*,
          m.title AS movie_title,
          tp.adult_price AS global_adult_price,
          tp.child_price AS global_child_price,
          tp.senior_price AS global_senior_price
        FROM showtimes s
        JOIN movies m ON m.id = s.movie_id
        CROSS JOIN ticket_prices tp
        ORDER BY
          s.show_date ASC,
          s.show_time ASC;
      `);

      res.json(result.rows.map(formatShowtime));
    } catch (error) {
      console.error(
        "Error obteniendo tandas:",
        error
      );

      res.status(500).json({
        error: "No se pudieron obtener las tandas."
      });
    }
  }
);

app.post(
  "/api/admin/showtimes",
  requireAdmin,
  async (req, res) => {
    try {
      const {
        movieId,
        showDate,
        showTime,
        language = "spanish",
        active = true
      } = req.body;

      if (
        typeof movieId !== "string" ||
        !movieId.trim()
      ) {
        return res.status(400).json({
          error: "Debes seleccionar una pelÃ­cula."
        });
      }

      if (
        typeof showDate !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(showDate)
      ) {
        return res.status(400).json({
          error: "La fecha de la tanda no es vÃ¡lida."
        });
      }

      if (
        typeof showTime !== "string" ||
        !showTime.trim()
      ) {
        return res.status(400).json({
          error: "La hora de la tanda es obligatoria."
        });
      }

      const priceResult = await pool.query(`
        SELECT adult_price, child_price, senior_price
        FROM ticket_prices
        WHERE id = 1;
      `);

      const numericAdultPrice = Number(priceResult.rows[0].adult_price);
      const numericChildPrice = Number(priceResult.rows[0].child_price);
      const numericSeniorPrice = Number(priceResult.rows[0].senior_price);

      const normalizedLanguage = normalizeShowtimeLanguage(language);

      if (!normalizedLanguage) {
        return res.status(400).json({
          error: "El idioma de la tanda no es vÃ¡lido."
        });
      }

      const movieResult = await pool.query(
        `
          SELECT id
          FROM movies
          WHERE id = $1;
        `,
        [movieId]
      );

      if (movieResult.rowCount === 0) {
        return res.status(404).json({
          error: "La pelÃ­cula seleccionada no existe."
        });
      }

      const duplicateResult = await pool.query(
        `
          SELECT id
          FROM showtimes
          WHERE
            movie_id = $1
            AND show_date = $2
            AND show_time = $3;
        `,
        [
          movieId,
          showDate,
          showTime.trim()
        ]
      );

      if (duplicateResult.rowCount > 0) {
        return res.status(409).json({
          error:
            "Esta pelÃ­cula ya tiene una tanda en esa fecha y hora."
        });
      }

      const id = crypto.randomUUID();

      const result = await pool.query(
        `
          INSERT INTO showtimes (
            id,
            movie_id,
            show_date,
            show_time,
            price,
            adult_price,
            child_price,
            senior_price,
            language,
            active
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
          RETURNING *;
        `,
        [
          id,
          movieId,
          showDate,
          showTime.trim(),
          numericAdultPrice,
          numericAdultPrice,
          numericChildPrice,
          numericSeniorPrice,
          normalizedLanguage,
          Boolean(active)
        ]
      );

      const completeResult = await pool.query(
        `
          SELECT
            s.*,
            m.title AS movie_title,
            tp.adult_price AS global_adult_price,
            tp.child_price AS global_child_price,
            tp.senior_price AS global_senior_price
          FROM showtimes s
          JOIN movies m ON m.id = s.movie_id
          CROSS JOIN ticket_prices tp
          WHERE s.id = $1;
        `,
        [result.rows[0].id]
      );

      res.status(201).json(
        formatShowtime(completeResult.rows[0])
      );
    } catch (error) {
      console.error(
        "Error creando tanda:",
        error
      );

      res.status(500).json({
        error: "No se pudo crear la tanda."
      });
    }
  }
);

app.put(
  "/api/admin/showtimes/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const {
        movieId,
        showDate,
        showTime,
        language = "spanish",
        active = true
      } = req.body;

      if (
        typeof movieId !== "string" ||
        !movieId.trim()
      ) {
        return res.status(400).json({
          error: "Debes seleccionar una pelÃ­cula."
        });
      }

      if (
        typeof showDate !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(showDate)
      ) {
        return res.status(400).json({
          error: "La fecha de la tanda no es vÃ¡lida."
        });
      }

      if (
        typeof showTime !== "string" ||
        !showTime.trim()
      ) {
        return res.status(400).json({
          error: "La hora de la tanda es obligatoria."
        });
      }

      const priceResult = await pool.query(`
        SELECT adult_price, child_price, senior_price
        FROM ticket_prices
        WHERE id = 1;
      `);

      const numericAdultPrice = Number(priceResult.rows[0].adult_price);
      const numericChildPrice = Number(priceResult.rows[0].child_price);
      const numericSeniorPrice = Number(priceResult.rows[0].senior_price);

      const normalizedLanguage = normalizeShowtimeLanguage(language);

      if (!normalizedLanguage) {
        return res.status(400).json({
          error: "El idioma de la tanda no es vÃ¡lido."
        });
      }

      const movieResult = await pool.query(
        `
          SELECT id
          FROM movies
          WHERE id = $1;
        `,
        [movieId]
      );

      if (movieResult.rowCount === 0) {
        return res.status(404).json({
          error: "La pelÃ­cula seleccionada no existe."
        });
      }

      const duplicateResult = await pool.query(
        `
          SELECT id
          FROM showtimes
          WHERE
            movie_id = $1
            AND show_date = $2
            AND show_time = $3
            AND id <> $4;
        `,
        [
          movieId,
          showDate,
          showTime.trim(),
          id
        ]
      );

      if (duplicateResult.rowCount > 0) {
        return res.status(409).json({
          error:
            "Ya existe otra tanda para esa pelÃ­cula en esa fecha y hora."
        });
      }

      const result = await pool.query(
        `
          UPDATE showtimes
          SET
            movie_id = $1,
            show_date = $2,
            show_time = $3,
            price = $4,
            adult_price = $5,
            child_price = $6,
            senior_price = $7,
            language = $8,
            active = $9
          WHERE id = $10
          RETURNING *;
        `,
        [
          movieId,
          showDate,
          showTime.trim(),
          numericAdultPrice,
          numericAdultPrice,
          numericChildPrice,
          numericSeniorPrice,
          normalizedLanguage,
          Boolean(active),
          id
        ]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "Tanda no encontrada."
        });
      }

      const completeResult = await pool.query(
        `
          SELECT
            s.*,
            m.title AS movie_title,
            tp.adult_price AS global_adult_price,
            tp.child_price AS global_child_price,
            tp.senior_price AS global_senior_price
          FROM showtimes s
          JOIN movies m ON m.id = s.movie_id
          CROSS JOIN ticket_prices tp
          WHERE s.id = $1;
        `,
        [id]
      );

      res.json(
        formatShowtime(completeResult.rows[0])
      );
    } catch (error) {
      console.error(
        "Error actualizando tanda:",
        error
      );

      res.status(500).json({
        error: "No se pudo actualizar la tanda."
      });
    }
  }
);

app.delete(
  "/api/admin/showtimes",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        DELETE FROM showtimes;
      `);

      res.json({
        success: true,
        deleted: result.rowCount,
        message: `Se eliminaron ${result.rowCount} tandas.`
      });
    } catch (error) {
      console.error(
        "Error eliminando todas las tandas:",
        error
      );

      res.status(500).json({
        error: "No se pudieron eliminar todas las tandas."
      });
    }
  }
);

app.delete(
  "/api/admin/showtimes/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const result = await pool.query(
        `
          DELETE FROM showtimes
          WHERE id = $1
          RETURNING id;
        `,
        [id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "Tanda no encontrada."
        });
      }

      res.json({
        success: true,
        message: "Tanda eliminada correctamente."
      });
    } catch (error) {
      console.error(
        "Error eliminando tanda:",
        error
      );

      res.status(500).json({
        error: "No se pudo eliminar la tanda."
      });
    }
  }
);


const OFFICIAL_SEAT_IDS = (() => {
  const ids = new Set(["A1-WC", "A10-WC", "M1-WC", "M11-WC"]);

  for (let position = 2; position <= 9; position += 1) ids.add(`A${position}`);
  for (const rowName of ["B","C","D","E","F","G","H","I","J","K"]) {
    for (let position = 1; position <= 16; position += 1) ids.add(`${rowName}${position}`);
  }
  for (let position = 1; position <= 15; position += 1) ids.add(`L${position}`);
  for (let position = 2; position <= 11; position += 1) ids.add(`M${position}`);

  return ids;
})();

/*
==================================================
ASIENTOS OCUPADOS
==================================================
*/

app.get("/api/seats", async (req, res) => {
  try {
    const { showtimeId } = req.query;

    if (
      typeof showtimeId !== "string" ||
      !showtimeId.trim()
    ) {
      return res.status(400).json({
        error: "Debes indicar la tanda."
      });
    }

    const showtimeResult = await pool.query(
      `
        SELECT
          s.id,
          s.show_date,
          s.show_time,
          m.title AS movie_title
        FROM showtimes s
        JOIN movies m ON m.id = s.movie_id
        WHERE s.id = $1;
      `,
      [showtimeId]
    );

    if (showtimeResult.rowCount === 0) {
      return res.status(404).json({
        error: "Tanda no encontrada."
      });
    }

    const ticketResult = await pool.query(
      `
        SELECT seats
        FROM tickets
        WHERE
          customer->>'showtimeId' = $1
          AND payment_status IN (
            'paid',
            'approved'
          );
      `,
      [showtimeId]
    );

    const occupiedSeats = [
      ...new Set(
        ticketResult.rows.flatMap(
          (ticket) => ticket.seats || []
        )
      )
    ];

    res.json({
      showtimeId,
      occupiedSeats
    });
  } catch (error) {
    console.error(
      "Error obteniendo los asientos ocupados:",
      error
    );

    res.status(500).json({
      error:
        "No se pudieron obtener los asientos ocupados."
    });
  }
});

/*
==================================================
CREAR RESERVACIÃN
==================================================
*/

app.post("/api/reservations", async (req, res) => {
  const client = await pool.connect();

  try {

    const {
  showtimeId,
  seats,
  ticketTypes,
  paymentMethod = "",
  athTestApproved = false,
  customer
} = req.body;

if (
  paymentMethod === "ath_movil" &&
  ATH_TEST_MODE &&
  athTestApproved !== true
) {
  return res.status(400).json({
    error: "El pago de prueba de ATH Móvil no fue aprobado."
  });
}

    if (
      typeof showtimeId !== "string" ||
      !showtimeId.trim()
    ) {
      return res.status(400).json({
        error: "Debes seleccionar una tanda."
      });
    }

    if (
      !Array.isArray(seats) ||
      seats.length === 0
    ) {
      return res.status(400).json({
        error: "Debes seleccionar al menos un asiento."
      });
    }

    const normalizedSeats = [
      ...new Set(
        seats
          .filter(
            (seat) =>
              typeof seat === "string" &&
              seat.trim()
          )
          .map((seat) => seat.trim().toUpperCase())
      )
    ];

    if (normalizedSeats.length === 0) {
      return res.status(400).json({
        error: "Los asientos seleccionados no son vÃ¡lidos."
      });
    }

    const invalidSeats = normalizedSeats.filter(
      (seat) => !OFFICIAL_SEAT_IDS.has(seat)
    );

    if (invalidSeats.length > 0) {
      return res.status(400).json({
        error: "Uno o más asientos no pertenecen al mapa oficial.",
        invalidSeats
      });
    }

    const normalizedTicketTypes = {
      adult: Math.max(0, Number.parseInt(ticketTypes?.adult, 10) || 0),
      child: Math.max(0, Number.parseInt(ticketTypes?.child, 10) || 0),
      senior: Math.max(0, Number.parseInt(ticketTypes?.senior, 10) || 0)
    };

    const ticketTypeCount =
      normalizedTicketTypes.adult +
      normalizedTicketTypes.child +
      normalizedTicketTypes.senior;

    if (ticketTypeCount !== normalizedSeats.length) {
      return res.status(400).json({
        error:
          "La cantidad de taquillas por categorÃ­a debe coincidir con los asientos seleccionados."
      });
    }

    if (
      !customer ||
      typeof customer !== "object"
    ) {
      return res.status(400).json({
        error: "Faltan los datos del cliente."
      });
    }

    const customerName =
      typeof customer.name === "string"
        ? customer.name.trim()
        : "";

    const customerEmail =
      typeof customer.email === "string"
        ? customer.email.trim()
        : "";

    const customerPhone =
      typeof customer.phone === "string"
        ? customer.phone.trim()
        : "";

    if (!customerName) {
      return res.status(400).json({
        error: "El nombre del cliente es obligatorio."
      });
    }

    await client.query("BEGIN");

    const showtimeResult = await client.query(
      `
        SELECT
          s.id,
          s.show_date,
          s.show_time,
          s.price,
          tp.adult_price AS global_adult_price,
          tp.child_price AS global_child_price,
          tp.senior_price AS global_senior_price,
          s.active,
          m.title AS movie_title,
          m.active AS movie_active
        FROM showtimes s
        JOIN movies m ON m.id = s.movie_id
        CROSS JOIN ticket_prices tp
        WHERE s.id = $1
        FOR UPDATE OF s;
      `,
      [showtimeId]
    );

    if (showtimeResult.rowCount === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "La tanda seleccionada no existe."
      });
    }

    const showtime = showtimeResult.rows[0];

    if (
      !showtime.active ||
      !showtime.movie_active
    ) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Esta tanda no estÃ¡ disponible."
      });
    }

    const occupiedResult = await client.query(
      `
        SELECT seats
        FROM tickets
        WHERE
          customer->>'showtimeId' = $1
          AND payment_status IN (
            'paid',
            'approved'
          )
        FOR UPDATE;
      `,
      [showtimeId]
    );

    const occupiedSeats = new Set(
      occupiedResult.rows.flatMap(
        (ticket) => ticket.seats || []
      )
    );

    const unavailableSeats =
      normalizedSeats.filter(
        (seat) => occupiedSeats.has(seat)
      );

    if (unavailableSeats.length > 0) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        error:
          "Uno o mÃ¡s asientos ya fueron reservados.",
        unavailableSeats
      });
    }

    const ticketId = crypto.randomUUID();
    const qrToken = crypto.randomBytes(32).toString("hex");
    const manualCode = await generateUniqueManualCode(client);
    const adultPrice = Number(showtime.global_adult_price);
    const childPrice = Number(showtime.global_child_price);
    const seniorPrice = Number(showtime.global_senior_price);

    const total =
      normalizedTicketTypes.adult * adultPrice +
      normalizedTicketTypes.child * childPrice +
      normalizedTicketTypes.senior * seniorPrice;

const initialPaymentStatus =
  paymentMethod === "ath_movil" &&
  ATH_TEST_MODE &&
  athTestApproved === true
    ? "paid"
    : "pending";

    const storedCustomer = {
      ...customer,
      name: customerName,
      email: customerEmail,
      phone: customerPhone,
      showtimeId,
      paymentMethod: ["paypal", "ath_movil"].includes(paymentMethod)
        ? paymentMethod
        : ""
    };

    const result = await client.query(
      `
        INSERT INTO tickets (
          id,
          movie,
          show_time,
          seats,
          total,
          customer,
          payment_status,
          qr,
          manual_code,
          used,
          ticket_breakdown
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8,
          $9,
          FALSE,
          $10
        )
        RETURNING *;
      `,
      [
        ticketId,
        showtime.movie_title,
        `${showtime.show_date} ${showtime.show_time}`,
        normalizedSeats,
        total,
        JSON.stringify(storedCustomer),
        initialPaymentStatus,
        qrToken,
        manualCode,
        JSON.stringify(normalizedTicketTypes)
      ]
    );

    await client.query("COMMIT");

    res.status(201).json({
  success: true,
  reservation: formatTicket(result.rows[0])
});
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(
      "Error creando la reservaciÃ3n:",
      error
    );

    res.status(500).json({
      error: "No se pudo crear la reservaciÃ3n."
    });
  } finally {
    client.release();
  }
});


/*
==================================================
CANCELAR RESERVACIÓN PENDIENTE
==================================================

Este endpoint SOLO elimina reservaciones que todavía estén
en estado "pending". Una reservación pagada nunca se borra aquí.
*/

app.delete("/api/reservations/:id/cancel", async (req, res) => {
  try {
    const reservationId = String(req.params.id || "").trim();

    if (!reservationId) {
      return res.status(400).json({
        error: "Falta la reservación."
      });
    }

    const result = await pool.query(
      `
        DELETE FROM tickets
        WHERE id = $1
          AND payment_status = 'pending'
        RETURNING id;
      `,
      [reservationId]
    );

    if (result.rowCount > 0) {
      return res.json({
        success: true,
        removed: true
      });
    }

    const existing = await pool.query(
      `
        SELECT payment_status
        FROM tickets
        WHERE id = $1;
      `,
      [reservationId]
    );

    if (existing.rowCount === 0) {
      return res.json({
        success: true,
        removed: false,
        message: "La reservación ya no existe."
      });
    }

    return res.status(409).json({
      error: "La reservación ya fue pagada o no puede cancelarse."
    });
  } catch (error) {
    console.error(
      "Error cancelando reservación pendiente:",
      error
    );

    res.status(500).json({
      error: "No se pudo cancelar la reservación."
    });
  }
});

/*
==================================================
PAYPAL CHECKOUT
==================================================
*/

app.get("/api/paypal/config", (req, res) => {
  res.json({
    enabled: paypalIsConfigured(),
    clientId: paypalIsConfigured() ? PAYPAL_CLIENT_ID : "",
    currency: PAYPAL_CURRENCY,
    mode: PAYPAL_MODE
  });
});

app.post("/api/paypal/orders", async (req, res) => {
  try {
    if (!paypalIsConfigured()) {
      return res.status(503).json({
        error: "PayPal todavía no está configurado en Render."
      });
    }

    const reservationId = String(req.body?.reservationId || "").trim();
    if (!reservationId) {
      return res.status(400).json({ error: "Falta la reservación." });
    }

    const ticketResult = await pool.query(
      `SELECT * FROM tickets WHERE id = $1;`,
      [reservationId]
    );

    if (ticketResult.rowCount === 0) {
      return res.status(404).json({ error: "Reservación no encontrada." });
    }

    const ticket = ticketResult.rows[0];
    if (ticket.payment_status !== "pending") {
      return res.status(400).json({
        error: "Esta reservación ya fue pagada o no puede procesarse."
      });
    }

    if (ticket.customer?.paymentMethod !== "paypal") {
      return res.status(400).json({
        error: "La reservación no fue creada para PayPal."
      });
    }

    const total = Number(ticket.total).toFixed(2);
    const order = await paypalRequest("/v2/checkout/orders", {
      method: "POST",
      headers: {
        "PayPal-Request-Id": `cine-${reservationId}`
      },
      body: JSON.stringify({
        intent: "CAPTURE",
        purchase_units: [
          {
            custom_id: reservationId,
            invoice_id: reservationId,
            description: `Boletos - ${ticket.movie}`.slice(0, 127),
            amount: {
              currency_code: PAYPAL_CURRENCY,
              value: total
            }
          }
        ],
        application_context: {
          brand_name: "Cine Teatro Manuel Nieves Quintero",
          shipping_preference: "NO_SHIPPING",
          user_action: "PAY_NOW"
        }
      })
    });

    res.status(201).json({ orderId: order.id });
  } catch (error) {
    console.error("Error creando orden de PayPal:", error);
    res.status(502).json({
      error: error.message || "No se pudo crear la orden de PayPal."
    });
  }
});

app.post("/api/paypal/orders/:orderId/capture", async (req, res) => {
  const client = await pool.connect();

  try {
    const orderId = String(req.params.orderId || "").trim();
    const reservationId = String(req.body?.reservationId || "").trim();

    if (!orderId || !reservationId) {
      return res.status(400).json({
        error: "Faltan los datos de la orden de PayPal."
      });
    }

    const capture = await paypalRequest(
      `/v2/checkout/orders/${encodeURIComponent(orderId)}/capture`,
      {
        method: "POST",
        headers: {
          "PayPal-Request-Id": `capture-${orderId}`
        },
        body: "{}"
      }
    );

    const purchaseUnit = capture.purchase_units?.[0];
    const capturedPayment = purchaseUnit?.payments?.captures?.[0];
    const capturedAmount = capturedPayment?.amount;
    const paypalReservationId = String(
  capturedPayment?.custom_id ||
  capturedPayment?.invoice_id ||
  purchaseUnit?.custom_id ||
  purchaseUnit?.invoice_id ||
  ""
).trim();

const requestedReservationId = String(
  reservationId || ""
).trim();

    if (capture.status !== "COMPLETED" || capturedPayment?.status !== "COMPLETED") {
      return res.status(400).json({
        error: "PayPal no confirmó el pago como completado."
      });
    }

    if (
  !paypalReservationId ||
  paypalReservationId !== requestedReservationId
) {
      return res.status(400).json({
        error: "La orden de PayPal no corresponde a esta reservación."
      });
    }

    await client.query("BEGIN");

    const ticketResult = await client.query(
      `SELECT * FROM tickets WHERE id = $1 FOR UPDATE;`,
      [reservationId]
    );

    if (ticketResult.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Reservación no encontrada." });
    }

    const ticket = ticketResult.rows[0];
    const expectedAmount = Number(ticket.total).toFixed(2);

    if (
      capturedAmount?.currency_code !== PAYPAL_CURRENCY ||
      Number(capturedAmount?.value).toFixed(2) !== expectedAmount
    ) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: "El total confirmado por PayPal no coincide con la reservación."
      });
    }

    if (
  ticket.payment_status === "paid" ||
  ticket.payment_status === "approved"
) {
  await client.query("COMMIT");

  return res.json({
    success: true,
    reservation: formatTicket(ticket)
  });
}

const updatedCustomer = {
  ...(ticket.customer || {}),
  paymentMethod: "paypal",
  paypalOrderId: orderId,
  paypalCaptureId: capturedPayment.id || "",
  paypalPayerEmail: capture.payer?.email_address || ""
};
    const updateResult = await client.query(
      `
        UPDATE tickets
        SET payment_status = 'paid', customer = $2
        WHERE id = $1
        RETURNING *;
      `,
      [reservationId, JSON.stringify(updatedCustomer)]
    );

    await client.query("COMMIT");

const reservation = formatTicket(updateResult.rows[0]);

try {
  await sendTicketEmail(reservation);
} catch (emailError) {
  console.error("Error enviando correo:", emailError);
}

res.json({
  success: true,
  reservation
});
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Error capturando pago de PayPal:", error);
    res.status(502).json({
      error: error.message || "No se pudo confirmar el pago de PayPal."
    });
  } finally {
    client.release();
  }
});

/*
==================================================
ATH MÓVIL MANUAL
==================================================
*/

app.post("/api/reservations/:id/ath-movil/submit", async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    const result = await pool.query(
      `SELECT * FROM tickets WHERE id = $1;`,
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Reservación no encontrada." });
    }

    const ticket = result.rows[0];
    if (ticket.customer?.paymentMethod !== "ath_movil") {
      return res.status(400).json({
        error: "La reservación no fue creada para ATH Móvil."
      });
    }

    if (ticket.payment_status !== "pending") {
      return res.status(400).json({
        error: "Esta reservación ya fue procesada."
      });
    }

    res.json({
      success: true,
      athMovilPhone: ATH_MOVIL_PHONE,
      reservation: formatTicket(ticket)
    });
  } catch (error) {
    console.error("Error registrando pago ATH Móvil:", error);
    res.status(500).json({
      error: "No se pudo registrar el pago enviado por ATH Móvil."
    });
  }
});

/*
==================================================
PAGO SIMULADO
==================================================
*/

app.post(
  "/api/reservations/:id/pay",
  async (req, res) => {
    try {
      const { id } = req.params;

      const result = await pool.query(
        `
          UPDATE tickets
          SET payment_status = 'paid'
          WHERE
            id = $1
            AND payment_status = 'pending'
          RETURNING *;
        `,
        [id]
      );

      if (result.rowCount === 0) {
        const existingResult = await pool.query(
          `
            SELECT *
            FROM tickets
            WHERE id = $1;
          `,
          [id]
        );

        if (existingResult.rowCount === 0) {
          return res.status(404).json({
            error: "ReservaciÃ3n no encontrada."
          });
        }

        return res.status(400).json({
          error:
            "La reservaciÃ3n ya fue pagada o no puede procesarse."
        });
      }

      res.json({
        success: true,
        message: "Pago aprobado.",
        reservation: formatTicket(result.rows[0])
      });
    } catch (error) {
      console.error(
        "Error procesando el pago:",
        error
      );

      res.status(500).json({
        error: "No se pudo procesar el pago."
      });
    }
  }
);

/*
==================================================
CONSULTAR BOLETO
==================================================
*/

app.get("/api/tickets/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `
        SELECT *
        FROM tickets
        WHERE id = $1;
      `,
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: "Boleto no encontrado."
      });
    }

    res.json(formatTicket(result.rows[0]));
  } catch (error) {
    console.error(
      "Error obteniendo el boleto:",
      error
    );

    res.status(500).json({
      error: "No se pudo obtener el boleto."
    });
  }
});

/*
==================================================
RESERVACIONES DEL PANEL ADMINISTRATIVO
==================================================
*/

app.get(
  "/api/admin/reservations",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT *
        FROM tickets
        ORDER BY created_at DESC;
      `);

      res.json(result.rows.map(formatTicket));
    } catch (error) {
      console.error(
        "Error obteniendo reservaciones:",
        error
      );

      res.status(500).json({
        error:
          "No se pudieron obtener las reservaciones."
      });
    }
  }
);

/*
==================================================
VALIDAR CÃDIGO QR
==================================================
*/

app.get("/api/qr/:qr", async (req, res) => {
  try {
    const { qr } = req.params;

    const result = await pool.query(
      `
        SELECT *
        FROM tickets
        WHERE qr = $1 OR manual_code = $1;
      `,
      [qr]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        valid: false,
        error: "Boleto no encontrado."
      });
    }

    const ticket = formatTicket(result.rows[0]);

    if (
      ticket.paymentStatus !== "paid" &&
      ticket.paymentStatus !== "approved"
    ) {
      return res.status(400).json({
        valid: false,
        error: "Este boleto no ha sido pagado.",
        ticket
      });
    }

    if (ticket.used) {
      return res.status(409).json({
        valid: false,
        error: "Este boleto ya fue utilizado.",
        ticket
      });
    }

    res.json({
      valid: true,
      message: "Boleto vÃ¡lido.",
      ticket
    });
  } catch (error) {
    console.error(
      "Error validando el cÃ3digo QR:",
      error
    );

    res.status(500).json({
      valid: false,
      error: "No se pudo validar el boleto."
    });
  }
});

/*
==================================================
CHECK-IN DEL EMPLEADO
==================================================
*/

app.post("/api/employee/checkin", requireEmployee, async (req, res) => {
  const client = await pool.connect();
  try {
    const code = String(
      req.body?.manualCode ||
      req.body?.qr ||
      req.body?.code ||
      ""
    ).trim();

    if (!code) {
      return res.status(400).json({
        error: "El cÃ3digo del boleto es obligatorio."
      });
    }

    await client.query("BEGIN");

    const ticketResult = await client.query(
      `
        SELECT *
        FROM tickets
        WHERE qr = $1 OR manual_code = $1
        FOR UPDATE;
      `,
      [code]
    );
    if (ticketResult.rowCount === 0) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Boleto no encontrado." }); }
    const ticket = ticketResult.rows[0];
    if (!["paid","approved"].includes(ticket.payment_status)) { await client.query("ROLLBACK"); return res.status(400).json({ error: "El boleto no ha sido pagado.", ticket: formatTicket(ticket) }); }
    if (ticket.used) {
      await client.query("ROLLBACK");
      const existing = await pool.query(`SELECT employee_name, scanned_at FROM checkins WHERE ticket_id=$1;`, [ticket.id]);
      return res.status(409).json({ error: "Este boleto ya fue utilizado.", ticket: formatTicket(ticket), checkin: existing.rows[0] || null });
    }
    const seatsCount = Array.isArray(ticket.seats) ? ticket.seats.length : 0;
    if (seatsCount <= 0) { await client.query("ROLLBACK"); return res.status(400).json({ error: "El boleto no contiene asientos vÃ¡lidos." }); }
    const updateResult = await client.query(`UPDATE tickets SET used=TRUE,checkin_at=NOW() WHERE id=$1 RETURNING *;`, [ticket.id]);
    await client.query(`INSERT INTO checkins (id,ticket_id,employee_id,employee_name,employee_username,seats_count,movie,show_time,seats) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9);`, [crypto.randomUUID(),ticket.id,req.employee.id,req.employee.name,req.employee.username,seatsCount,ticket.movie,ticket.show_time,ticket.seats]);
    await client.query("COMMIT");
    res.json({ success: true, message: `Entrada registrada por ${req.employee.name}. ${seatsCount} taquilla${seatsCount===1?"":"s"} contabilizada${seatsCount===1?"":"s"}.`, employee: { id:req.employee.id,name:req.employee.name,username:req.employee.username }, seatsCount, ticket: formatTicket(updateResult.rows[0]) });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Error registrando check-in de empleado:", error);
    res.status(500).json({ error: "No se pudo registrar la entrada." });
  } finally { client.release(); }
});

/*
==================================================
CHECK-IN DEL BOLETO
==================================================
*/

app.post(
  "/api/admin/checkin",
  requireAdmin,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const code = String(
        req.body?.manualCode ||
        req.body?.qr ||
        req.body?.code ||
        ""
      ).trim();

      if (!code) {
        return res.status(400).json({
          error: "El cÃ3digo del boleto es obligatorio."
        });
      }

      await client.query("BEGIN");

      const ticketResult = await client.query(
        `
          SELECT *
          FROM tickets
          WHERE qr = $1 OR manual_code = $1
          FOR UPDATE;
        `,
        [code]
      );

      if (ticketResult.rowCount === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Boleto no encontrado."
        });
      }

      const ticket = ticketResult.rows[0];

      if (
        ticket.payment_status !== "paid" &&
        ticket.payment_status !== "approved"
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error: "El boleto no ha sido pagado."
        });
      }

      if (ticket.used) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error: "Este boleto ya fue utilizado.",
          ticket: formatTicket(ticket)
        });
      }

      const updateResult = await client.query(
        `
          UPDATE tickets
          SET
            used = TRUE,
            checkin_at = NOW()
          WHERE id = $1
          RETURNING *;
        `,
        [ticket.id]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message: "Entrada registrada correctamente.",
        ticket: formatTicket(updateResult.rows[0])
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(
        "Error registrando el check-in:",
        error
      );

      res.status(500).json({
        error: "No se pudo registrar la entrada."
      });
    } finally {
      client.release();
    }
  }
);

/*
==================================================
SUBIR TRÃILER A SUPABASE STORAGE
==================================================
*/

app.post(
  "/api/admin/trailers",
  requireAdmin,
  trailerUpload.single("trailer"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: "Selecciona un video para el trÃ¡iler."
        });
      }

      const extension =
        trailerExtensionFromMimeType(
          req.file.mimetype
        );

      const fileName =
        `${Date.now()}-${crypto.randomUUID()}.${extension}`;

      const filePath =
        `trailers/${fileName}`;

      const { error: uploadError } =
        await supabase.storage
          .from(SUPABASE_TRAILERS_BUCKET)
          .upload(
            filePath,
            req.file.buffer,
            {
              contentType: req.file.mimetype,
              cacheControl: "31536000",
              upsert: false
            }
          );

      if (uploadError) {
        console.error(
          "Error de Supabase subiendo trÃ¡iler:",
          uploadError
        );

        return res.status(502).json({
          error:
            uploadError.message ||
            "No se pudo subir el trÃ¡iler a Supabase Storage."
        });
      }

      const { data: publicUrlData } =
        supabase.storage
          .from(SUPABASE_TRAILERS_BUCKET)
          .getPublicUrl(filePath);

      if (!publicUrlData?.publicUrl) {
        return res.status(500).json({
          error:
            "El trÃ¡iler se subiÃ3, pero no se pudo obtener su URL pÃoblica."
        });
      }

      res.status(201).json({
        success: true,
        trailerUrl:
          publicUrlData.publicUrl,
        path: filePath
      });
    } catch (error) {
      console.error(
        "Error subiendo trÃ¡iler:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo subir el trÃ¡iler."
      });
    }
  }
);

/*
==================================================
RUTA NO ENCONTRADA
==================================================
*/

app.use((req, res) => {
  res.status(404).json({
    error: "Ruta no encontrada."
  });
});

/*
==================================================
MANEJO GENERAL DE ERRORES
==================================================
*/

app.use((error, req, res, next) => {
  console.error("Error inesperado:", error);

  if (res.headersSent) {
    return next(error);
  }

  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      const isTrailer =
        req.path.includes("/trailers");

      return res.status(413).json({
        error: isTrailer
          ? "El trÃ¡iler es demasiado grande. El mÃ¡ximo es 50 MB."
          : "El afiche es demasiado grande. El mÃ¡ximo es 6 MB."
      });
    }

    return res.status(400).json({
      error: "No se pudo procesar el archivo."
    });
  }

  if (
    error?.message ===
      "El afiche debe ser JPG, PNG o WEBP." ||
    error?.message ===
      "El trÃ¡iler debe ser MP4, WEBM o MOV."
  ) {
    return res.status(400).json({
      error: error.message
    });
  }

  res.status(500).json({
    error: "OcurriÃ3 un error inesperado."
  });
});

/*
==================================================
INICIAR SERVIDOR
==================================================
*/

async function startServer() {
  try {
    await initializeDatabase();
    await cleanupPreviousBusinessDay();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Servidor iniciado correctamente en el puerto ${PORT}.`
      );
    });
  } catch (error) {
    console.error(
      "No se pudo iniciar el servidor:",
      error
    );

    process.exit(1);
  }
}

startServer();
