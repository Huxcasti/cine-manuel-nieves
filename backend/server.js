const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

if (!process.env.DATABASE_URL) {
  console.error("Falta la variable DATABASE_URL.");
  process.exit(1);
}

const useSSL = process.env.DATABASE_URL.includes("render.com");

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
Convertir los nombres de PostgreSQL al formato
que espera nuestra página web
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
Crear la tabla automáticamente
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
      used BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      checkin_at TIMESTAMPTZ
    );
  `);

  console.log("Base de datos preparada correctamente.");
}

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
      app: "Cine Teatro Manuel Nieves Quintero",
      version: "2.0"
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
        total,
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
      return res.json({
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
Obtener todas las reservaciones
Este endpoint luego estará protegido con contraseña
==================================================
*/

app.get("/api/reservations", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM tickets
      ORDER BY created_at DESC;
    `);

    res.json(result.rows.map(formatTicket));
  } catch (error) {
    console.error("Error obteniendo reservaciones:", error);

    res.status(500).json({
      error: "No se pudieron obtener las reservaciones."
    });
  }
});

/*
==================================================
Iniciar el servidor después de preparar PostgreSQL
==================================================
*/

async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(`Servidor iniciado en el puerto ${PORT}.`);
    });
  } catch (error) {
    console.error("No se pudo iniciar el servidor:", error);
    process.exit(1);
  }
}

startServer();
