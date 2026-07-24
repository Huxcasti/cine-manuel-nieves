const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

/*
==================================================
CLAVE DEL PANEL ADMINISTRATIVO
==================================================

La contraseña debe estar configurada en Render
como una variable llamada ADMIN_KEY.
*/

const ADMIN_KEY = process.env.ADMIN_KEY;

app.use(cors());
app.use(express.json());

/*
==================================================
Verificar variables necesarias
==================================================
*/

if (!process.env.DATABASE_URL) {
  console.error("Falta la variable DATABASE_URL.");
  process.exit(1);
}

if (!ADMIN_KEY) {
  console.error("Falta la variable ADMIN_KEY.");
  process.exit(1);
}

/*
==================================================
Conexión con PostgreSQL
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
Convertir las taquillas de PostgreSQL al formato
que espera la página web
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
    used: row.used,
    created: row.created_at,
    checkin: row.checkin_at
  };
}

/*
==================================================
Convertir las películas al formato web
==================================================
*/

function formatMovie(row) {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    posterUrl: row.poster_url,
    durationMinutes: row.duration_minutes,
    rating: row.rating,
    active: row.active,
    created: row.created_at
  };
}

/*
==================================================
Convertir las tandas al formato web
==================================================
*/

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

/*
==================================================
Crear las tablas automáticamente
==================================================
*/

async function initializeDatabase() {
  /*
  Taquillas y reservaciones
  */

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
      used BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      checkin_at TIMESTAMPTZ
    );
  `);

  /*
  Películas
  */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS movies (
      id UUID PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      poster_url TEXT,
      duration_minutes INTEGER,
      rating TEXT,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  /*
  Tandas
  */

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
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("Base de datos preparada correctamente.");
}

/*
==================================================
Reinicio diario a las 3:00 a. m.
Zona horaria: Puerto Rico
==================================================

El día operacional funciona desde las 3:00 a. m.
hasta las 2:59 a. m. del día siguiente.

Solamente se eliminan las taquillas y reservaciones.
Las películas y las tandas no se borran.
*/

async function cleanupPreviousBusinessDay() {
  const result = await pool.query(`
    DELETE FROM tickets
    WHERE created_at < (
      (
        CASE
          WHEN
            (NOW() AT TIME ZONE 'America/Puerto_Rico')::time
            >= TIME '03:00:00'
          THEN
            DATE_TRUNC(
              'day',
              NOW() AT TIME ZONE 'America/Puerto_Rico'
            ) + INTERVAL '3 hours'
          ELSE
            DATE_TRUNC(
              'day',
              NOW() AT TIME ZONE 'America/Puerto_Rico'
            ) - INTERVAL '21 hours'
        END
      ) AT TIME ZONE 'America/Puerto_Rico'
    );
  `);

  if (result.rowCount > 0) {
    console.log(
      `Reinicio diario completado: ${result.rowCount} reservaciones eliminadas.`
    );
  }
}

/*
==================================================
Comprobar el reinicio cuando el servidor recibe uso
==================================================
*/

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
    console.error("Error realizando el reinicio diario:", error);
  }

  next();
});

/*
==================================================
Servidor funcionando
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
      version: "3.0"
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
Crear una reservación
==================================================
*/

app.post("/api/reservation", async (req, res) => {
  try {
    const { movie, time, seats, total, customer } = req.body;

    if (
      !movie ||
      !time ||
      !Array.isArray(seats) ||
      seats.length === 0 ||
      !customer ||
      !customer.name ||
      !customer.email ||
      !customer.phone
    ) {
      return res.status(400).json({
        error: "Faltan datos de la reservación."
      });
    }

    const numericTotal = Number(total);

    if (!Number.isFinite(numericTotal) || numericTotal <= 0) {
      return res.status(400).json({
        error: "El total de la reservación no es válido."
      });
    }

    const id = crypto.randomUUID();
    const qr = crypto.randomBytes(24).toString("hex");

    const result = await pool.query(
      `
        INSERT INTO tickets (
          id,
          movie,
          show_time,
          seats,
          total,
          customer,
          payment_status,
          qr
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *;
      `,
      [
        id,
        movie,
        time,
        seats,
        numericTotal,
        customer,
        "pending",
        qr
      ]
    );

    res.status(201).json(formatTicket(result.rows[0]));
  } catch (error) {
    console.error("Error creando la reservación:", error);

    res.status(500).json({
      error: "No se pudo crear la reservación."
    });
  }
});

/*
==================================================
Marcar pago como completado
Todavía es una simulación
==================================================
*/

app.post("/api/pay/:id", async (req, res) => {
  try {
    const result = await pool.query(
      `
        UPDATE tickets
        SET payment_status = 'paid'
        WHERE id = $1
        RETURNING *;
      `,
      [req.params.id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: "Reservación no encontrada."
      });
    }

    res.json({
      success: true,
      ticket: formatTicket(result.rows[0])
    });
  } catch (error) {
    console.error("Error actualizando el pago:", error);

    res.status(500).json({
      error: "No se pudo actualizar el pago."
    });
  }
});

/*
==================================================
Validar un código QR
==================================================
*/

app.get("/api/qr/:code", async (req, res) => {
  try {
    const result = await pool.query(
      `
        SELECT *
        FROM tickets
        WHERE qr = $1;
      `,
      [req.params.code]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        valid: false,
        message: "Taquilla no encontrada."
      });
    }

    const ticket = formatTicket(result.rows[0]);

    if (ticket.paymentStatus !== "paid") {
      return res.status(400).json({
        valid: false,
        message: "El pago no ha sido confirmado.",
        ticket
      });
    }

    if (ticket.used) {
      return res.status(409).json({
        valid: false,
        message: "Esta taquilla ya fue utilizada.",
        ticket
      });
    }

    res.json({
      valid: true,
      message: "Taquilla válida.",
      ticket
    });
  } catch (error) {
    console.error("Error validando el QR:", error);

    res.status(500).json({
      valid: false,
      error: "No se pudo validar la taquilla."
    });
  }
});

/*
==================================================
Escanear y utilizar una taquilla
==================================================
*/

app.post("/api/checkin/:code", async (req, res) => {
  try {
    const result = await pool.query(
      `
        UPDATE tickets
        SET
          used = TRUE,
          checkin_at = NOW()
        WHERE
          qr = $1
          AND used = FALSE
          AND payment_status = 'paid'
        RETURNING *;
      `,
      [req.params.code]
    );

    if (result.rowCount > 0) {
      return res.json({
        success: true,
        message: "Entrada autorizada.",
        ticket: formatTicket(result.rows[0])
      });
    }

    const existingResult = await pool.query(
      `
        SELECT *
        FROM tickets
        WHERE qr = $1;
      `,
      [req.params.code]
    );

    if (existingResult.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Taquilla no encontrada."
      });
    }

    const ticket = formatTicket(existingResult.rows[0]);

    if (ticket.paymentStatus !== "paid") {
      return res.status(400).json({
        success: false,
        message: "El pago de esta taquilla no está confirmado.",
        ticket
      });
    }

    return res.status(409).json({
      success: false,
      message: "Esta taquilla ya fue utilizada.",
      ticket
    });
  } catch (error) {
    console.error("Error procesando la entrada:", error);

    res.status(500).json({
      success: false,
      message: "No se pudo procesar la entrada."
    });
  }
});

/*
==================================================
Reservaciones del panel administrativo
==================================================
*/

app.get("/api/admin/reservations", async (req, res) => {
  const providedKey = req.headers["x-admin-key"];

  if (!providedKey || providedKey !== ADMIN_KEY) {
    return res.status(401).json({
      error: "Acceso denegado."
    });
  }

  try {
    const result = await pool.query(`
      SELECT *
      FROM tickets
      ORDER BY created_at DESC;
    `);

    res.json(result.rows.map(formatTicket));
  } catch (error) {
    console.error(
      "Error obteniendo las reservaciones administrativas:",
      error
    );

    res.status(500).json({
      error: "No se pudieron obtener las reservaciones."
    });
  }
});

/*
==================================================
Ruta pública bloqueada por seguridad
==================================================
*/

app.get("/api/reservations", (req, res) => {
  res.status(403).json({
    error: "Esta información requiere acceso administrativo."
  });
});

/*
==================================================
Ruta no encontrada
==================================================
*/

app.use((req, res) => {
  res.status(404).json({
    error: "Ruta no encontrada."
  });
});

/*
==================================================
Iniciar el servidor
==================================================
*/

async function startServer() {
  try {
    await initializeDatabase();
    await cleanupPreviousBusinessDay();

    app.listen(PORT, () => {
      console.log(`Servidor iniciado en el puerto ${PORT}.`);
      console.log(
        "Las ventas se reinician diariamente a las 3:00 a. m. de Puerto Rico."
      );
      console.log("Las tablas de películas y tandas están preparadas.");
    });
  } catch (error) {
    console.error("No se pudo iniciar el servidor:", error);
    process.exit(1);
  }
}

startServer();
