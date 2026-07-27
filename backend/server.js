const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

/*
==================================================
VARIABLES DE ENTORNO
==================================================
*/

const INITIAL_ADMIN_PASSWORD = process.env.ADMIN_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;
const SUPABASE_POSTERS_BUCKET =
  process.env.SUPABASE_POSTERS_BUCKET || "posters";

const SUPABASE_TRAILERS_BUCKET =
  process.env.SUPABASE_TRAILERS_BUCKET || "trailers";

app.use(cors());
app.use(express.json({ limit: "1mb" }));

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
  console.error("Falta la variable SUPABASE_SERVICE_ROLE_KEY.");
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
        new Error("El afiche debe ser JPG, PNG o WEBP.")
      );
      return;
    }

    callback(null, true);
  }
});

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
        new Error("El trÃ¡iler debe ser MP4, WEBM o MOV.")
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
    "image/webp": "webp",
    "video/mp4": "mp4",
    "video/webm": "webm",
    "video/quicktime": "mov"
  };

  return extensions[mimeType] || "bin";
}

/*
==================================================
SEGURIDAD Y CONTRASEÃAS
==================================================
*/

function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      64,
      (error, derivedKey) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(derivedKey);
      }
    );
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

async function verifyPassword(
  password,
  storedSalt,
  storedHash
) {
  const derivedKey = await scryptAsync(
    password,
    storedSalt
  );

  const storedBuffer = Buffer.from(
    storedHash,
    "hex"
  );

  if (storedBuffer.length !== derivedKey.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    storedBuffer,
    derivedKey
  );
}

function hashSessionToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function normalizeUsername(username) {
  return String(username || "")
    .trim()
    .toLowerCase();
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
    const providedPassword =
      req.headers["x-admin-key"];

    const valid = await isValidAdminPassword(
      providedPassword
    );

    if (!valid) {
      return res.status(401).json({
        error: "Acceso denegado."
      });
    }

    next();
  } catch (error) {
    console.error(
      "Error verificando acceso administrativo:",
      error
    );

    res.status(500).json({
      error:
        "No se pudo verificar el acceso administrativo."
    });
  }
}

async function requireEmployee(req, res, next) {
  try {
    const token =
      req.headers["x-employee-token"];

    if (!token || typeof token !== "string") {
      return res.status(401).json({
        error:
          "Debes iniciar sesiÃ³n como empleado."
      });
    }

    const tokenHash = hashSessionToken(token);

    const result = await pool.query(
      `
        SELECT
          e.id,
          e.name,
          e.username,
          e.active
        FROM employee_sessions s
        JOIN employees e
          ON e.id = s.employee_id
        WHERE
          s.token_hash = $1
          AND s.expires_at > NOW()
          AND e.active = TRUE;
      `,
      [tokenHash]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        error:
          "La sesiÃ³n del empleado expirÃ³ o no es vÃ¡lida."
      });
    }

    req.employee = result.rows[0];
    req.employeeTokenHash = tokenHash;

    next();
  } catch (error) {
    console.error(
      "Error verificando al empleado:",
      error
    );

    res.status(500).json({
      error:
        "No se pudo verificar la sesiÃ³n del empleado."
    });
  }
}

/*
==================================================
CÃDIGO MANUAL DE CINCO DÃGITOS
==================================================
*/

const BLOCKED_MANUAL_CODES = new Set([
  "11111",
  "22222",
  "33333",
  "44444",
  "55555",
  "66666",
  "77777",
  "88888",
  "99999",
  "12345",
  "23456",
  "34567",
  "45678",
  "56789",
  "98765",
  "87654",
  "76543",
  "65432",
  "54321"
]);

function isObviousManualCode(code) {
  const normalized = String(code || "").trim();

  if (!/^\d{5}$/.test(normalized)) {
    return true;
  }

  if (BLOCKED_MANUAL_CODES.has(normalized)) {
    return true;
  }

  const digits = normalized.split("").map(Number);

  const allEqual = digits.every(
    (digit) => digit === digits[0]
  );

  if (allEqual) {
    return true;
  }

  const ascending = digits.every(
    (digit, index) =>
      index === 0 ||
      digit === digits[index - 1] + 1
  );

  if (ascending) {
    return true;
  }

  const descending = digits.every(
    (digit, index) =>
      index === 0 ||
      digit === digits[index - 1] - 1
  );

  if (descending) {
    return true;
  }

  return false;
}

function generateFiveDigitCode() {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const code = String(
      crypto.randomInt(10000, 100000)
    );

    if (!isObviousManualCode(code)) {
      return code;
    }
  }

  throw new Error(
    "No se pudo generar un cÃ³digo manual seguro."
  );
}

function normalizeTicketLookup(value) {
  let text = String(value || "").trim();

  if (!text) {
    return "";
  }

  try {
    const url = new URL(text);

    const valueFromQuery =
      url.searchParams.get("code") ||
      url.searchParams.get("qr") ||
      url.searchParams.get("manualCode") ||
      url.searchParams.get("ticket") ||
      url.searchParams.get("token");

    if (valueFromQuery) {
      text = valueFromQuery.trim();
    } else {
      const pathParts = url.pathname
        .split("/")
        .filter(Boolean);

      if (pathParts.length > 0) {
        const lastPart =
          pathParts[pathParts.length - 1];

        if (
          /^[a-f0-9]{32,}$/i.test(lastPart) ||
          /^\d{5}$/.test(lastPart)
        ) {
          text = decodeURIComponent(lastPart);
        }
      }
    }
  } catch (error) {
    // No era una URL. Se usa el valor original.
  }

  return text.trim();
}

async function assignManualCodeToExistingTicket(
  ticketId
) {
  for (let attempt = 0; attempt < 250; attempt += 1) {
    const manualCode = generateFiveDigitCode();

    const result = await pool.query(
      `
        UPDATE tickets
        SET manual_code = $1
        WHERE
          id = $2
          AND manual_code IS NULL
          AND NOT EXISTS (
            SELECT 1
            FROM tickets
            WHERE manual_code = $1
          )
        RETURNING manual_code;
      `,
      [manualCode, ticketId]
    );

    if (result.rowCount > 0) {
      return result.rows[0].manual_code;
    }

    const currentResult = await pool.query(
      `
        SELECT manual_code
        FROM tickets
        WHERE id = $1;
      `,
      [ticketId]
    );

    const existingCode =
      currentResult.rows[0]?.manual_code;

    if (existingCode) {
      return existingCode;
    }
  }

  throw new Error(
    "No se pudo generar el cÃ³digo manual del boleto."
  );
}

/*
==================================================
FORMATEADORES
==================================================
*/

function formatTicket(row) {
  return {
    id: row.id,
    movie: row.movie,
    time: row.show_time,
    seats: row.seats,
    total: Number(row.total),
    customer: row.customer,
    paymentStatus: row.payment_status,
    qr: row.qr,
    manualCode: row.manual_code || null,
    used: row.used,
    created: row.created_at,
    checkin: row.checkin_at
  };
}

function formatMovie(row) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    posterUrl: row.poster_url,
    trailerUrl: row.trailer_url || "",
    durationMinutes: row.duration_minutes,
    rating: row.rating,
    active: row.active,
    created: row.created_at
  };
}

function formatShowtime(row) {
  return {
    id: row.id,
    movieId: row.movie_id,
    movieTitle: row.movie_title,
    showDate: row.show_date,
    showTime: row.show_time,
    price: Number(row.price),
    active: row.active,
    created: row.created_at
  };
}

function formatEmployee(row) {
  return {
    id: row.id,
    name: row.name,
    username: row.username,
    active: row.active,
    created: row.created_at,
    scans: Number(row.scans || 0),
    ticketsScanned: Number(
      row.tickets_scanned || 0
    ),
    lastScan: row.last_scan || null
  };
}

function formatCheckin(row) {
  return {
    id: row.id,
    ticketId: row.ticket_id,
    employeeId: row.employee_id,
    employeeName: row.employee_name,
    employeeUsername: row.employee_username,
    seatsCount: Number(row.seats_count || 0),
    movie: row.movie,
    showTime: row.show_time,
    seats: row.seats || [],
    scannedAt: row.scanned_at
  };
}

/*
==================================================
CREAR Y ACTUALIZAR TABLAS
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
      payment_status TEXT NOT NULL
        DEFAULT 'pending',
      qr TEXT UNIQUE NOT NULL,
      manual_code VARCHAR(5),
      used BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),
      checkin_at TIMESTAMPTZ
    );
  `);

  await pool.query(`
    ALTER TABLE tickets
    ADD COLUMN IF NOT EXISTS manual_code VARCHAR(5);
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
      tickets_manual_code_unique
    ON tickets (manual_code)
    WHERE manual_code IS NOT NULL;
  `);

  await pool.query(`
    ALTER TABLE tickets
    DROP CONSTRAINT IF EXISTS
      tickets_manual_code_format_check;
  `);

  await pool.query(`
    ALTER TABLE tickets
    ADD CONSTRAINT
      tickets_manual_code_format_check
    CHECK (
      manual_code IS NULL
      OR manual_code ~ '^[1-9][0-9]{4}$'
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      tickets_created_at_idx
    ON tickets (created_at DESC);
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
      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
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
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
      showtimes_movie_date_time_unique
    ON showtimes (
      movie_id,
      show_date,
      show_time
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS employees (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
      employees_username_lower_unique
    ON employees (LOWER(username));
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS employee_sessions (
      id UUID PRIMARY KEY,
      employee_id UUID NOT NULL
        REFERENCES employees(id)
        ON DELETE CASCADE,
      token_hash TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      employee_sessions_expires_at_idx
    ON employee_sessions (expires_at);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS checkins (
      id UUID PRIMARY KEY,
      ticket_id UUID UNIQUE NOT NULL
        REFERENCES tickets(id)
        ON DELETE CASCADE,
      employee_id UUID
        REFERENCES employees(id)
        ON DELETE SET NULL,
      employee_name TEXT NOT NULL,
      employee_username TEXT NOT NULL,
      seats_count INTEGER NOT NULL
        CHECK (seats_count > 0),
      movie TEXT NOT NULL,
      show_time TEXT NOT NULL,
      seats TEXT[] NOT NULL,
      scanned_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      checkins_employee_id_idx
    ON checkins (employee_id);
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      checkins_scanned_at_idx
    ON checkins (scanned_at DESC);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW()
    );
  `);

  const adminResult = await pool.query(`
    SELECT id
    FROM admin_settings
    WHERE id = 1;
  `);

  if (adminResult.rowCount === 0) {
    const initialCredentials =
      await hashPassword(
        INITIAL_ADMIN_PASSWORD
      );

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

    console.log(
      "ContraseÃ±a administrativa inicial creada."
    );
  }

  await pool.query(`
    UPDATE tickets
    SET manual_code = NULL
    WHERE
      manual_code = '00000'
      OR manual_code !~ '^[0-9]{5}$';
  `);

  const ticketsWithoutCode = await pool.query(`
    SELECT id
    FROM tickets
    WHERE manual_code IS NULL;
  `);

  for (const ticket of ticketsWithoutCode.rows) {
    await assignManualCodeToExistingTicket(
      ticket.id
    );
  }

  console.log(
    "Base de datos preparada correctamente."
  );
}

/*
==================================================
REINICIO DIARIO A LAS 3:00 A. M.
HORA DE PUERTO RICO
==================================================
*/

async function cleanupPreviousBusinessDay() {
  await pool.query(`
    DELETE FROM employee_sessions
    WHERE expires_at <= NOW();
  `);

  const result = await pool.query(`
    DELETE FROM tickets
    WHERE created_at < (
      (
        CASE
          WHEN
            (
              NOW()
              AT TIME ZONE 'America/Puerto_Rico'
            )::time >= TIME '03:00:00'
          THEN
            DATE_TRUNC(
              'day',
              NOW()
              AT TIME ZONE 'America/Puerto_Rico'
            ) + INTERVAL '3 hours'
          ELSE
            DATE_TRUNC(
              'day',
              NOW()
              AT TIME ZONE 'America/Puerto_Rico'
            ) - INTERVAL '21 hours'
        END
      ) AT TIME ZONE 'America/Puerto_Rico'
    );
  `);

  if (result.rowCount > 0) {
    console.log(
      `Reinicio diario completado: ` +
      `${result.rowCount} reservaciones eliminadas.`
    );
  }
}

let lastCleanupCheck = 0;

app.use(async (req, res, next) => {
  const now = Date.now();

  if (now - lastCleanupCheck < 60_000) {
    return next();
  }

  lastCleanupCheck = now;

  try {
    await cleanupPreviousBusinessDay();
  } catch (error) {
    console.error(
      "Error realizando el reinicio diario:",
      error
    );
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
      dailyReset:
        "3:00 AM America/Puerto_Rico",
      app:
        "Cine Teatro Manuel Nieves Quintero",
      version: "6.0",
      manualTicketCode: "5 digits"
    });
  } catch (error) {
    console.error(
      "Error verificando la base de datos:",
      error
    );

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
        m.title AS movie_title
      FROM showtimes s
      JOIN movies m
        ON m.id = s.movie_id
      WHERE
        s.active = TRUE
        AND m.active = TRUE
        AND s.show_date >= (
          NOW()
          AT TIME ZONE 'America/Puerto_Rico'
        )::date
      ORDER BY
        s.show_date ASC,
        s.show_time ASC;
    `);

    const showtimes =
      showtimeResult.rows.map(
        formatShowtime
      );

    const movies = movieResult.rows.map(
      (row) => {
        const movie = formatMovie(row);

        return {
          ...movie,
          showtimes: showtimes.filter(
            (showtime) =>
              showtime.movieId === movie.id
          )
        };
      }
    );

    res.json(movies);
  } catch (error) {
    console.error(
      "Error obteniendo la cartelera:",
      error
    );

    res.status(500).json({
      error:
        "No se pudo obtener la cartelera."
    });
  }
});

/*
==================================================
AUTENTICACIÃN DEL ADMINISTRADOR
==================================================
*/

app.post("/api/admin/login", async (req, res) => {
  try {
    const { password } = req.body;

    const valid =
      await isValidAdminPassword(password);

    if (!valid) {
      return res.status(401).json({
        error: "ContraseÃ±a incorrecta."
      });
    }

    res.json({
      success: true,
      message: "Acceso autorizado."
    });
  } catch (error) {
    console.error(
      "Error iniciando sesiÃ³n:",
      error
    );

    res.status(500).json({
      error: "No se pudo iniciar sesiÃ³n."
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
        await isValidAdminPassword(
          currentPassword
        );

      if (!currentPasswordValid) {
        return res.status(401).json({
          error:
            "La contraseÃ±a actual es incorrecta."
        });
      }

      if (
        typeof newPassword !== "string" ||
        newPassword.length < 8
      ) {
        return res.status(400).json({
          error:
            "La nueva contraseÃ±a debe tener al menos 8 caracteres."
        });
      }

      if (newPassword === currentPassword) {
        return res.status(400).json({
          error:
            "La nueva contraseÃ±a debe ser diferente a la actual."
        });
      }

      const credentials =
        await hashPassword(newPassword);

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
        message:
          "ContraseÃ±a actualizada correctamente."
      });
    } catch (error) {
      console.error(
        "Error cambiando la contraseÃ±a:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo cambiar la contraseÃ±a."
      });
    }
  }
);

/*
==================================================
CUENTAS Y SESIONES DE EMPLEADOS
==================================================
*/

app.post(
  "/api/employee/login",
  async (req, res) => {
    try {
      const username = normalizeUsername(
        req.body?.username
      );

      const password = req.body?.password;

      if (
        !username ||
        typeof password !== "string"
      ) {
        return res.status(400).json({
          error:
            "Escribe el usuario y la contraseÃ±a."
        });
      }

      const result = await pool.query(
        `
          SELECT *
          FROM employees
          WHERE LOWER(username) = $1;
        `,
        [username]
      );

      if (result.rowCount === 0) {
        return res.status(401).json({
          error:
            "Usuario o contraseÃ±a incorrectos."
        });
      }

      const employee = result.rows[0];

      if (!employee.active) {
        return res.status(403).json({
          error:
            "Esta cuenta estÃ¡ desactivada."
        });
      }

      const valid = await verifyPassword(
        password,
        employee.password_salt,
        employee.password_hash
      );

      if (!valid) {
        return res.status(401).json({
          error:
            "Usuario o contraseÃ±a incorrectos."
        });
      }

      const token =
        crypto.randomBytes(32).toString("hex");

      await pool.query(
        `
          INSERT INTO employee_sessions (
            id,
            employee_id,
            token_hash,
            expires_at
          )
          VALUES (
            $1,
            $2,
            $3,
            NOW() + INTERVAL '12 hours'
          );
        `,
        [
          crypto.randomUUID(),
          employee.id,
          hashSessionToken(token)
        ]
      );

      res.json({
        success: true,
        token,
        expiresInHours: 12,
        employee: {
          id: employee.id,
          name: employee.name,
          username: employee.username
        }
      });
    } catch (error) {
      console.error(
        "Error iniciando sesiÃ³n de empleado:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo iniciar la sesiÃ³n."
      });
    }
  }
);

app.get(
  "/api/employee/me",
  requireEmployee,
  async (req, res) => {
    res.json({
      employee: {
        id: req.employee.id,
        name: req.employee.name,
        username: req.employee.username
      }
    });
  }
);

app.post(
  "/api/employee/logout",
  requireEmployee,
  async (req, res) => {
    try {
      await pool.query(
        `
          DELETE FROM employee_sessions
          WHERE token_hash = $1;
        `,
        [req.employeeTokenHash]
      );

      res.json({
        success: true,
        message:
          "SesiÃ³n cerrada correctamente."
      });
    } catch (error) {
      console.error(
        "Error cerrando sesiÃ³n de empleado:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo cerrar la sesiÃ³n."
      });
    }
  }
);

/*
==================================================
ADMINISTRACIÃN DE EMPLEADOS
==================================================
*/

app.get(
  "/api/admin/employees",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          e.*,
          COUNT(c.id) AS scans,
          COALESCE(
            SUM(c.seats_count),
            0
          ) AS tickets_scanned,
          MAX(c.scanned_at) AS last_scan
        FROM employees e
        LEFT JOIN checkins c
          ON c.employee_id = e.id
        GROUP BY e.id
        ORDER BY e.name ASC;
      `);

      res.json(
        result.rows.map(formatEmployee)
      );
    } catch (error) {
      console.error(
        "Error obteniendo empleados:",
        error
      );

      res.status(500).json({
        error:
          "No se pudieron obtener los empleados."
      });
    }
  }
);

app.post(
  "/api/admin/employees",
  requireAdmin,
  async (req, res) => {
    try {
      const name = String(
        req.body?.name || ""
      ).trim();

      const username = normalizeUsername(
        req.body?.username
      );

      const password = req.body?.password;
      const active =
        req.body?.active !== false;

      if (!name) {
        return res.status(400).json({
          error:
            "El nombre del empleado es obligatorio."
        });
      }

      if (
        !/^[a-z0-9._-]{3,30}$/.test(
          username
        )
      ) {
        return res.status(400).json({
          error:
            "El usuario debe tener entre 3 y 30 caracteres y solo puede usar letras, nÃºmeros, punto, guion o guion bajo."
        });
      }

      if (
        typeof password !== "string" ||
        password.length < 8
      ) {
        return res.status(400).json({
          error:
            "La contraseÃ±a debe tener al menos 8 caracteres."
        });
      }

      const credentials =
        await hashPassword(password);

      const result = await pool.query(
        `
          INSERT INTO employees (
            id,
            name,
            username,
            password_salt,
            password_hash,
            active
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6
          )
          RETURNING *;
        `,
        [
          crypto.randomUUID(),
          name,
          username,
          credentials.salt,
          credentials.hash,
          Boolean(active)
        ]
      );

      res.status(201).json(
        formatEmployee(result.rows[0])
      );
    } catch (error) {
      if (error?.code === "23505") {
        return res.status(409).json({
          error:
            "Ese nombre de usuario ya estÃ¡ registrado."
        });
      }

      console.error(
        "Error creando empleado:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo crear el empleado."
      });
    }
  }
);

app.put(
  "/api/admin/employees/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const name = String(
        req.body?.name || ""
      ).trim();

      const username = normalizeUsername(
        req.body?.username
      );

      const password = req.body?.password;
      const active =
        req.body?.active !== false;

      if (!name) {
        return res.status(400).json({
          error:
            "El nombre del empleado es obligatorio."
        });
      }

      if (
        !/^[a-z0-9._-]{3,30}$/.test(
          username
        )
      ) {
        return res.status(400).json({
          error:
            "El nombre de usuario no es vÃ¡lido."
        });
      }

      let result;

      if (
        typeof password === "string" &&
        password.length > 0
      ) {
        if (password.length < 8) {
          return res.status(400).json({
            error:
              "La contraseÃ±a debe tener al menos 8 caracteres."
          });
        }

        const credentials =
          await hashPassword(password);

        result = await pool.query(
          `
            UPDATE employees
            SET
              name = $1,
              username = $2,
              password_salt = $3,
              password_hash = $4,
              active = $5,
              updated_at = NOW()
            WHERE id = $6
            RETURNING *;
          `,
          [
            name,
            username,
            credentials.salt,
            credentials.hash,
            Boolean(active),
            id
          ]
        );

        await pool.query(
          `
            DELETE FROM employee_sessions
            WHERE employee_id = $1;
          `,
          [id]
        );
      } else {
        result = await pool.query(
          `
            UPDATE employees
            SET
              name = $1,
              username = $2,
              active = $3,
              updated_at = NOW()
            WHERE id = $4
            RETURNING *;
          `,
          [
            name,
            username,
            Boolean(active),
            id
          ]
        );

        if (!active) {
          await pool.query(
            `
              DELETE FROM employee_sessions
              WHERE employee_id = $1;
            `,
            [id]
          );
        }
      }

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "Empleado no encontrado."
        });
      }

      res.json(
        formatEmployee(result.rows[0])
      );
    } catch (error) {
      if (error?.code === "23505") {
        return res.status(409).json({
          error:
            "Ese nombre de usuario ya estÃ¡ registrado."
        });
      }

      console.error(
        "Error actualizando empleado:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo actualizar el empleado."
      });
    }
  }
);

app.delete(
  "/api/admin/employees/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
          DELETE FROM employees
          WHERE id = $1
          RETURNING id;
        `,
        [req.params.id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "Empleado no encontrado."
        });
      }

      res.json({
        success: true,
        message:
          "Empleado eliminado. Su historial de escaneos se conserva."
      });
    } catch (error) {
      console.error(
        "Error eliminando empleado:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo eliminar el empleado."
      });
    }
  }
);

app.get(
  "/api/admin/checkins",
  requireAdmin,
  async (req, res) => {
    try {
      const limit = Math.min(
        Math.max(
          Number(req.query.limit) || 200,
          1
        ),
        1000
      );

      const result = await pool.query(
        `
          SELECT *
          FROM checkins
          ORDER BY scanned_at DESC
          LIMIT $1;
        `,
        [limit]
      );

      res.json(
        result.rows.map(formatCheckin)
      );
    } catch (error) {
      console.error(
        "Error obteniendo historial de escaneos:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo obtener el historial de escaneos."
      });
    }
  }
);

/*
==================================================
SUBIR AFICHE
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
          error:
            "Selecciona una imagen para el afiche."
        });
      }

      const extension =
        extensionFromMimeType(
          req.file.mimetype
        );

      const fileName =
        `${Date.now()}-` +
        `${crypto.randomUUID()}.` +
        `${extension}`;

      const filePath =
        `movies/${fileName}`;

      const { error: uploadError } =
        await supabase.storage
          .from(SUPABASE_POSTERS_BUCKET)
          .upload(
            filePath,
            req.file.buffer,
            {
              contentType:
                req.file.mimetype,
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
            "El afiche se subiÃ³, pero no se pudo obtener su URL pÃºblica."
        });
      }

      res.status(201).json({
        success: true,
        posterUrl:
          publicUrlData.publicUrl,
        path: filePath
      });
    } catch (error) {
      console.error(
        "Error subiendo afiche:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo subir el afiche."
      });
    }
  }
);

/*
==================================================
SUBIR TRÃILER
Mantiene un solo trÃ¡iler almacenado.
Antes de subir uno nuevo, elimina el anterior.
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
          error:
            "Selecciona un video para el trÃ¡iler."
        });
      }

      const extension =
        extensionFromMimeType(
          req.file.mimetype
        );

      const folderName = "current";

      const {
        data: existingFiles,
        error: listError
      } = await supabase.storage
        .from(SUPABASE_TRAILERS_BUCKET)
        .list(
          folderName,
          {
            limit: 100,
            offset: 0
          }
        );

      if (listError) {
        console.error(
          "Error consultando trÃ¡ilers anteriores:",
          listError
        );

        return res.status(502).json({
          error:
            "No se pudo revisar el almacenamiento de trÃ¡ilers. Verifica que el bucket trailers exista y sea pÃºblico."
        });
      }

      if (
        Array.isArray(existingFiles) &&
        existingFiles.length > 0
      ) {
        const pathsToRemove =
          existingFiles
            .filter(
              (file) =>
                file?.name &&
                file.name !== ".emptyFolderPlaceholder"
            )
            .map(
              (file) =>
                `${folderName}/${file.name}`
            );

        if (pathsToRemove.length > 0) {
          const {
            error: removeError
          } = await supabase.storage
            .from(SUPABASE_TRAILERS_BUCKET)
            .remove(pathsToRemove);

          if (removeError) {
            console.error(
              "Error eliminando el trÃ¡iler anterior:",
              removeError
            );

            return res.status(502).json({
              error:
                "No se pudo eliminar el trÃ¡iler anterior."
            });
          }
        }
      }

      const fileName =
        `${Date.now()}-` +
        `${crypto.randomUUID()}.` +
        `${extension}`;

      const filePath =
        `${folderName}/${fileName}`;

      const {
        error: uploadError
      } = await supabase.storage
        .from(SUPABASE_TRAILERS_BUCKET)
        .upload(
          filePath,
          req.file.buffer,
          {
            contentType:
              req.file.mimetype,
            cacheControl: "3600",
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

      const {
        data: publicUrlData
      } = supabase.storage
        .from(SUPABASE_TRAILERS_BUCKET)
        .getPublicUrl(filePath);

      if (!publicUrlData?.publicUrl) {
        return res.status(500).json({
          error:
            "El trÃ¡iler se subiÃ³, pero no se pudo obtener su URL pÃºblica."
        });
      }

      await pool.query(
        `
          UPDATE movies
          SET trailer_url = NULL
          WHERE trailer_url IS NOT NULL;
        `
      );

      res.status(201).json({
        success: true,
        message:
          "TrÃ¡iler anterior eliminado y nuevo trÃ¡iler subido correctamente.",
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

      res.json(
        result.rows.map(formatMovie)
      );
    } catch (error) {
      console.error(
        "Error obteniendo pelÃ­culas:",
        error
      );

      res.status(500).json({
        error:
          "No se pudieron obtener las pelÃ­culas."
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
        active = true
      } = req.body;

      if (
        typeof title !== "string" ||
        !title.trim()
      ) {
        return res.status(400).json({
          error:
            "El tÃ­tulo de la pelÃ­cula es obligatorio."
        });
      }

      if (
        durationMinutes !== null &&
        (
          !Number.isInteger(
            Number(durationMinutes)
          ) ||
          Number(durationMinutes) <= 0
        )
      ) {
        return res.status(400).json({
          error:
            "La duraciÃ³n debe ser un nÃºmero entero mayor que cero."
        });
      }

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
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8
          )
          RETURNING *;
        `,
        [
          crypto.randomUUID(),
          title.trim(),
          String(description).trim(),
          String(posterUrl).trim(),
          String(trailerUrl).trim(),
          durationMinutes === null
            ? null
            : Number(durationMinutes),
          String(rating).trim(),
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
        error:
          "No se pudo crear la pelÃ­cula."
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
        active = true
      } = req.body;

      if (
        typeof title !== "string" ||
        !title.trim()
      ) {
        return res.status(400).json({
          error:
            "El tÃ­tulo de la pelÃ­cula es obligatorio."
        });
      }

      if (
        durationMinutes !== null &&
        (
          !Number.isInteger(
            Number(durationMinutes)
          ) ||
          Number(durationMinutes) <= 0
        )
      ) {
        return res.status(400).json({
          error:
            "La duraciÃ³n debe ser un nÃºmero entero mayor que cero."
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
            active = $7
          WHERE id = $8
          RETURNING *;
        `,
        [
          title.trim(),
          String(description).trim(),
          String(posterUrl).trim(),
          String(trailerUrl).trim(),
          durationMinutes === null
            ? null
            : Number(durationMinutes),
          String(rating).trim(),
          Boolean(active),
          id
        ]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "PelÃ­cula no encontrada."
        });
      }

      res.json(
        formatMovie(result.rows[0])
      );
    } catch (error) {
      console.error(
        "Error actualizando pelÃ­cula:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo actualizar la pelÃ­cula."
      });
    }
  }
);

app.delete(
  "/api/admin/movies/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
          DELETE FROM movies
          WHERE id = $1
          RETURNING id;
        `,
        [req.params.id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "PelÃ­cula no encontrada."
        });
      }

      res.json({
        success: true,
        message:
          "PelÃ­cula eliminada correctamente."
      });
    } catch (error) {
      console.error(
        "Error eliminando pelÃ­cula:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo eliminar la pelÃ­cula."
      });
    }
  }
);

/*
==================================================
ADMINISTRACIÃN DE TANDAS
==================================================
*/

function validateShowtimeData(body) {
  const movieId = String(
    body?.movieId || ""
  ).trim();

  const showDate = String(
    body?.showDate || ""
  ).trim();

  const showTime = String(
    body?.showTime || ""
  ).trim();

  const numericPrice = Number(body?.price);

  if (!movieId) {
    return {
      error:
        "Debes seleccionar una pelÃ­cula."
    };
  }

  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(
      showDate
    )
  ) {
    return {
      error:
        "La fecha de la tanda no es vÃ¡lida."
    };
  }

  if (
    !/^\d{2}:\d{2}(:\d{2})?$/.test(
      showTime
    )
  ) {
    return {
      error:
        "La hora de la tanda no es vÃ¡lida."
    };
  }

  if (
    !Number.isFinite(numericPrice) ||
    numericPrice < 0
  ) {
    return {
      error:
        "El precio de la tanda no es vÃ¡lido."
    };
  }

  return {
    movieId,
    showDate,
    showTime: showTime.slice(0, 5),
    numericPrice,
    active: body?.active !== false
  };
}

app.get(
  "/api/admin/showtimes",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          s.*,
          m.title AS movie_title
        FROM showtimes s
        JOIN movies m
          ON m.id = s.movie_id
        ORDER BY
          s.show_date ASC,
          s.show_time ASC;
      `);

      res.json(
        result.rows.map(formatShowtime)
      );
    } catch (error) {
      console.error(
        "Error obteniendo tandas:",
        error
      );

      res.status(500).json({
        error:
          "No se pudieron obtener las tandas."
      });
    }
  }
);

app.post(
  "/api/admin/showtimes",
  requireAdmin,
  async (req, res) => {
    try {
      const validated =
        validateShowtimeData(req.body);

      if (validated.error) {
        return res.status(400).json({
          error: validated.error
        });
      }

      const movieResult = await pool.query(
        `
          SELECT id
          FROM movies
          WHERE id = $1;
        `,
        [validated.movieId]
      );

      if (movieResult.rowCount === 0) {
        return res.status(404).json({
          error:
            "La pelÃ­cula seleccionada no existe."
        });
      }

      const result = await pool.query(
        `
          INSERT INTO showtimes (
            id,
            movie_id,
            show_date,
            show_time,
            price,
            active
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6
          )
          RETURNING *;
        `,
        [
          crypto.randomUUID(),
          validated.movieId,
          validated.showDate,
          validated.showTime,
          validated.numericPrice,
          Boolean(validated.active)
        ]
      );

      const completeResult = await pool.query(
        `
          SELECT
            s.*,
            m.title AS movie_title
          FROM showtimes s
          JOIN movies m
            ON m.id = s.movie_id
          WHERE s.id = $1;
        `,
        [result.rows[0].id]
      );

      res.status(201).json(
        formatShowtime(
          completeResult.rows[0]
        )
      );
    } catch (error) {
      if (error?.code === "23505") {
        return res.status(409).json({
          error:
            "Esta pelÃ­cula ya tiene una tanda en esa fecha y hora."
        });
      }

      console.error(
        "Error creando tanda:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo crear la tanda."
      });
    }
  }
);

app.put(
  "/api/admin/showtimes/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const validated =
        validateShowtimeData(req.body);

      if (validated.error) {
        return res.status(400).json({
          error: validated.error
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
            active = $5
          WHERE id = $6
          RETURNING *;
        `,
        [
          validated.movieId,
          validated.showDate,
          validated.showTime,
          validated.numericPrice,
          Boolean(validated.active),
          req.params.id
        ]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "Tanda no encontrada."
        });
      }

      const completeResult = await pool.query(
        `
          SELECT
            s.*,
            m.title AS movie_title
          FROM showtimes s
          JOIN movies m
            ON m.id = s.movie_id
          WHERE s.id = $1;
        `,
        [req.params.id]
      );

      res.json(
        formatShowtime(
          completeResult.rows[0]
        )
      );
    } catch (error) {
      if (error?.code === "23505") {
        return res.status(409).json({
          error:
            "Ya existe otra tanda para esa pelÃ­cula en esa fecha y hora."
        });
      }

      console.error(
        "Error actualizando tanda:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo actualizar la tanda."
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
        message:
          `Se eliminaron ${result.rowCount} tandas.`
      });
    } catch (error) {
      console.error(
        "Error eliminando todas las tandas:",
        error
      );

      res.status(500).json({
        error:
          "No se pudieron eliminar todas las tandas."
      });
    }
  }
);

app.delete(
  "/api/admin/showtimes/:id",
  requireAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
          DELETE FROM showtimes
          WHERE id = $1
          RETURNING id;
        `,
        [req.params.id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "Tanda no encontrada."
        });
      }

      res.json({
        success: true,
        message:
          "Tanda eliminada correctamente."
      });
    } catch (error) {
      console.error(
        "Error eliminando tanda:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo eliminar la tanda."
      });
    }
  }
);

/*
==================================================
ASIENTOS OCUPADOS
==================================================
*/

app.get("/api/seats", async (req, res) => {
  try {
    const showtimeId = String(
      req.query?.showtimeId || ""
    ).trim();

    if (!showtimeId) {
      return res.status(400).json({
        error:
          "Debes indicar la tanda."
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
        JOIN movies m
          ON m.id = s.movie_id
        WHERE s.id = $1;
      `,
      [showtimeId]
    );

    if (showtimeResult.rowCount === 0) {
      return res.status(404).json({
        error:
          "Tanda no encontrada."
      });
    }

    const ticketResult = await pool.query(
      `
        SELECT seats
        FROM tickets
        WHERE
          customer->>'showtimeId' = $1
          AND payment_status IN (
            'pending',
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

app.post(
  "/api/reservations",
  async (req, res) => {
    const client = await pool.connect();

    try {
      const {
        showtimeId,
        seats,
        customer
      } = req.body;

      if (
        typeof showtimeId !== "string" ||
        !showtimeId.trim()
      ) {
        return res.status(400).json({
          error:
            "Debes seleccionar una tanda."
        });
      }

      if (
        !Array.isArray(seats) ||
        seats.length === 0
      ) {
        return res.status(400).json({
          error:
            "Debes seleccionar al menos un asiento."
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
            .map(
              (seat) =>
                seat.trim().toUpperCase()
            )
        )
      ];

      if (normalizedSeats.length === 0) {
        return res.status(400).json({
          error:
            "Los asientos seleccionados no son vÃ¡lidos."
        });
      }

      if (
        !customer ||
        typeof customer !== "object"
      ) {
        return res.status(400).json({
          error:
            "Faltan los datos del cliente."
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
          error:
            "El nombre del cliente es obligatorio."
        });
      }

      await client.query("BEGIN");

      const showtimeResult =
        await client.query(
          `
            SELECT
              s.id,
              s.show_date,
              s.show_time,
              s.price,
              s.active,
              m.title AS movie_title,
              m.active AS movie_active
            FROM showtimes s
            JOIN movies m
              ON m.id = s.movie_id
            WHERE s.id = $1
            FOR UPDATE;
          `,
          [showtimeId]
        );

      if (
        showtimeResult.rowCount === 0
      ) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error:
            "La tanda seleccionada no existe."
        });
      }

      const showtime =
        showtimeResult.rows[0];

      if (
        !showtime.active ||
        !showtime.movie_active
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "Esta tanda no estÃ¡ disponible."
        });
      }

      const occupiedResult =
        await client.query(
          `
            SELECT seats
            FROM tickets
            WHERE
              customer->>'showtimeId' = $1
              AND payment_status IN (
                'pending',
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
          (seat) =>
            occupiedSeats.has(seat)
        );

      if (
        unavailableSeats.length > 0
      ) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error:
            "Uno o mÃ¡s asientos ya fueron reservados.",
          unavailableSeats
        });
      }

      const ticketId =
        crypto.randomUUID();

      const qrToken =
        crypto
          .randomBytes(32)
          .toString("hex");

      const ticketPrice =
        Number(showtime.price);

      const total =
        ticketPrice *
        normalizedSeats.length;

      const storedCustomer = {
        ...customer,
        name: customerName,
        email: customerEmail,
        phone: customerPhone,
        showtimeId
      };

      let insertedTicket = null;

      for (
        let attempt = 0;
        attempt < 250;
        attempt += 1
      ) {
        const manualCode =
          generateFiveDigitCode();

        const result =
          await client.query(
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
                used
              )
              VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                'pending',
                $7,
                $8,
                FALSE
              )
              ON CONFLICT DO NOTHING
              RETURNING *;
            `,
            [
              ticketId,
              showtime.movie_title,
              `${showtime.show_date} ` +
                `${showtime.show_time}`,
              normalizedSeats,
              total,
              JSON.stringify(
                storedCustomer
              ),
              qrToken,
              manualCode
            ]
          );

        if (result.rowCount > 0) {
          insertedTicket =
            result.rows[0];
          break;
        }
      }

      if (!insertedTicket) {
        throw new Error(
          "No se pudo generar un cÃ³digo manual Ãºnico y seguro."
        );
      }

      await client.query("COMMIT");

      res.status(201).json({
        success: true,
        reservation:
          formatTicket(insertedTicket)
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        console.error(
          "Error haciendo rollback:",
          rollbackError
        );
      }

      console.error(
        "Error creando la reservaciÃ³n:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo crear la reservaciÃ³n."
      });
    } finally {
      client.release();
    }
  }
);

/*
==================================================
PAGO SIMULADO
==================================================
*/

app.post(
  "/api/reservations/:id/pay",
  async (req, res) => {
    try {
      const result = await pool.query(
        `
          UPDATE tickets
          SET payment_status = 'paid'
          WHERE
            id = $1
            AND payment_status = 'pending'
          RETURNING *;
        `,
        [req.params.id]
      );

      if (result.rowCount === 0) {
        const existingResult =
          await pool.query(
            `
              SELECT *
              FROM tickets
              WHERE id = $1;
            `,
            [req.params.id]
          );

        if (
          existingResult.rowCount === 0
        ) {
          return res.status(404).json({
            error:
              "ReservaciÃ³n no encontrada."
          });
        }

        return res.status(400).json({
          error:
            "La reservaciÃ³n ya fue pagada o no puede procesarse."
        });
      }

      res.json({
        success: true,
        message: "Pago aprobado.",
        reservation:
          formatTicket(result.rows[0])
      });
    } catch (error) {
      console.error(
        "Error procesando el pago:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo procesar el pago."
      });
    }
  }
);

/*
==================================================
CONSULTAR BOLETO
==================================================
*/

app.get(
  "/api/tickets/:id",
  async (req, res) => {
    try {
      const result = await pool.query(
        `
          SELECT *
          FROM tickets
          WHERE id = $1;
        `,
        [req.params.id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "Boleto no encontrado."
        });
      }

      res.json(
        formatTicket(result.rows[0])
      );
    } catch (error) {
      console.error(
        "Error obteniendo el boleto:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo obtener el boleto."
      });
    }
  }
);

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

      res.json(
        result.rows.map(formatTicket)
      );
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
VALIDAR BOLETO SIN MARCARLO
Acepta el QR largo o el cÃ³digo manual de 5 dÃ­gitos.
==================================================
*/

app.get(
  "/api/qr/:code",
  async (req, res) => {
    try {
      const code = normalizeTicketLookup(
        req.params.code
      );

      const result = await pool.query(
        `
          SELECT *
          FROM tickets
          WHERE
            qr = $1
            OR manual_code = $1;
        `,
        [code]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          valid: false,
          error:
            "Boleto no encontrado."
        });
      }

      const ticket =
        formatTicket(result.rows[0]);

      if (
        ticket.paymentStatus !== "paid" &&
        ticket.paymentStatus !== "approved"
      ) {
        return res.status(400).json({
          valid: false,
          error:
            "Este boleto no ha sido pagado.",
          ticket
        });
      }

      if (ticket.used) {
        return res.status(409).json({
          valid: false,
          error:
            "Este boleto ya fue utilizado.",
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
        "Error validando el boleto:",
        error
      );

      res.status(500).json({
        valid: false,
        error:
          "No se pudo validar el boleto."
      });
    }
  }
);

/*
==================================================
CHECK-IN DEL EMPLEADO
Acepta:
- req.body.qr
- req.body.code
- req.body.manualCode
- req.body.rawCode
==================================================
*/

app.post(
  "/api/employee/checkin",
  requireEmployee,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const rawLookup =
        req.body?.qr ||
        req.body?.code ||
        req.body?.manualCode ||
        req.body?.rawCode ||
        "";

      const lookup =
        normalizeTicketLookup(rawLookup);

      if (!lookup) {
        return res.status(400).json({
          error:
            "El cÃ³digo del boleto es obligatorio."
        });
      }

      await client.query("BEGIN");

      const ticketResult =
        await client.query(
          `
            SELECT *
            FROM tickets
            WHERE
              qr = $1
              OR manual_code = $1
            FOR UPDATE;
          `,
          [lookup]
        );

      if (
        ticketResult.rowCount === 0
      ) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error:
            "Boleto no encontrado. Verifica el cÃ³digo de 5 dÃ­gitos."
        });
      }

      const ticket =
        ticketResult.rows[0];

      if (
        !["paid", "approved"].includes(
          ticket.payment_status
        )
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "El boleto no ha sido pagado.",
          ticket: formatTicket(ticket)
        });
      }

      if (ticket.used) {
        await client.query("ROLLBACK");

        const existing =
          await pool.query(
            `
              SELECT
                employee_name,
                scanned_at
              FROM checkins
              WHERE ticket_id = $1;
            `,
            [ticket.id]
          );

        return res.status(409).json({
          error:
            "Este boleto ya fue utilizado.",
          ticket: formatTicket(ticket),
          checkin:
            existing.rows[0] || null
        });
      }

      const seatsCount =
        Array.isArray(ticket.seats)
          ? ticket.seats.length
          : 0;

      if (seatsCount <= 0) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "El boleto no contiene asientos vÃ¡lidos."
        });
      }

      const updateResult =
        await client.query(
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

      const checkinResult =
        await client.query(
          `
            INSERT INTO checkins (
              id,
              ticket_id,
              employee_id,
              employee_name,
              employee_username,
              seats_count,
              movie,
              show_time,
              seats
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
              $9
            )
            RETURNING *;
          `,
          [
            crypto.randomUUID(),
            ticket.id,
            req.employee.id,
            req.employee.name,
            req.employee.username,
            seatsCount,
            ticket.movie,
            ticket.show_time,
            ticket.seats
          ]
        );

      await client.query("COMMIT");

      const formattedTicket =
        formatTicket(
          updateResult.rows[0]
        );

      res.json({
        success: true,
        message:
          `Entrada registrada por ` +
          `${req.employee.name}. ` +
          `${seatsCount} taquilla` +
          `${seatsCount === 1 ? "" : "s"} ` +
          `contabilizada` +
          `${seatsCount === 1 ? "" : "s"}.`,
        employee: {
          id: req.employee.id,
          name: req.employee.name,
          username: req.employee.username
        },
        seatsCount,
        movie: formattedTicket.movie,
        showTime: formattedTicket.time,
        seats: formattedTicket.seats,
        manualCode:
          formattedTicket.manualCode,
        validatedAt:
          checkinResult.rows[0].scanned_at,
        ticket: formattedTicket
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        console.error(
          "Error haciendo rollback:",
          rollbackError
        );
      }

      console.error(
        "Error registrando check-in de empleado:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo registrar la entrada."
      });
    } finally {
      client.release();
    }
  }
);

/*
==================================================
CHECK-IN ADMINISTRATIVO
==================================================
*/

app.post(
  "/api/admin/checkin",
  requireAdmin,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const lookup =
        normalizeTicketLookup(
          req.body?.qr ||
          req.body?.code ||
          req.body?.manualCode ||
          ""
        );

      if (!lookup) {
        return res.status(400).json({
          error:
            "El cÃ³digo del boleto es obligatorio."
        });
      }

      await client.query("BEGIN");

      const ticketResult =
        await client.query(
          `
            SELECT *
            FROM tickets
            WHERE
              qr = $1
              OR manual_code = $1
            FOR UPDATE;
          `,
          [lookup]
        );

      if (
        ticketResult.rowCount === 0
      ) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error:
            "Boleto no encontrado."
        });
      }

      const ticket =
        ticketResult.rows[0];

      if (
        !["paid", "approved"].includes(
          ticket.payment_status
        )
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "El boleto no ha sido pagado."
        });
      }

      if (ticket.used) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error:
            "Este boleto ya fue utilizado.",
          ticket: formatTicket(ticket)
        });
      }

      const updateResult =
        await client.query(
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
        message:
          "Entrada registrada correctamente.",
        ticket:
          formatTicket(
            updateResult.rows[0]
          )
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        console.error(
          "Error haciendo rollback:",
          rollbackError
        );
      }

      console.error(
        "Error registrando el check-in:",
        error
      );

      res.status(500).json({
        error:
          "No se pudo registrar la entrada."
      });
    } finally {
      client.release();
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
  console.error(
    "Error inesperado:",
    error
  );

  if (res.headersSent) {
    return next(error);
  }

  if (
    error instanceof multer.MulterError
  ) {
    if (
      error.code === "LIMIT_FILE_SIZE"
    ) {
      const isTrailer =
        req.path.includes("/trailers");

      return res.status(413).json({
        error: isTrailer
          ? "El trÃ¡iler es demasiado grande. El mÃ¡ximo permitido es 50 MB."
          : "El afiche es demasiado grande. El mÃ¡ximo es 6 MB."
      });
    }

    return res.status(400).json({
      error:
        "No se pudo procesar el archivo."
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
    error:
      "OcurriÃ³ un error inesperado."
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

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Servidor iniciado correctamente ` +
          `en el puerto ${PORT}.`
        );
      }
    );
  } catch (error) {
    console.error(
      "No se pudo iniciar el servidor:",
      error
    );

    process.exit(1);
  }
}

startServer();
