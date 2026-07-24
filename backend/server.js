const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

/*
==================================================
VARIABLES DE ENTORNO
==================================================
*/

const INITIAL_ADMIN_PASSWORD = process.env.ADMIN_KEY;

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

/*
==================================================
CONEXIÓN CON POSTGRESQL
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
CONTRASEÑA DEL ADMINISTRADOR
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

/*
==================================================
CREAR TABLAS AUTOMÁTICAMENTE
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
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

    console.log("Contraseña administrativa inicial creada.");
  }

  console.log("Base de datos preparada correctamente.");
}

/*
==================================================
REINICIO DIARIO A LAS 3:00 A. M.
HORA DE PUERTO RICO
==================================================

Solo elimina reservaciones y taquillas.
No elimina películas, tandas ni contraseña.
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
      version: "4.0"
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
CARTELERA PÚBLICA
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
      JOIN movies m ON m.id = s.movie_id
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
AUTENTICACIÓN DEL ADMINISTRADOR
==================================================
*/

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
    console.error("Error iniciando sesión:", error);

    res.status(500).json({
      error: "No se pudo iniciar sesión."
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
        "Error cambiando la contraseña:",
        error
      );

      res.status(500).json({
        error: "No se pudo cambiar la contraseña."
      });
    }
  }
);

/*
==================================================
ADMINISTRACIÓN DE PELÍCULAS
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
        "Error obteniendo películas:",
        error
      );

      res.status(500).json({
        error: "No se pudieron obtener las películas."
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
        durationMinutes = null,
        rating = "",
        active = true
      } = req.body;

      if (
        typeof title !== "string" ||
        !title.trim()
      ) {
        return res.status(400).json({
          error: "El título de la película es obligatorio."
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
            "La duración debe ser un número entero mayor que cero."
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
            duration_minutes,
            rating,
            active
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          RETURNING *;
        `,
        [
          id,
          title.trim(),
          description.trim(),
          posterUrl.trim(),
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
        "Error creando película:",
        error
      );

      res.status(500).json({
        error: "No se pudo crear la película."
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
        durationMinutes = null,
        rating = "",
        active = true
      } = req.body;

      if (
        typeof title !== "string" ||
        !title.trim()
      ) {
        return res.status(400).json({
          error: "El título de la película es obligatorio."
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
            "La duración debe ser un número entero mayor que cero."
        });
      }

      const result = await pool.query(
        `
          UPDATE movies
          SET
            title = $1,
            description = $2,
            poster_url = $3,
            duration_minutes = $4,
            rating = $5,
            active = $6
          WHERE id = $7
          RETURNING *;
        `,
        [
          title.trim(),
          description.trim(),
          posterUrl.trim(),
          durationMinutes === null
            ? null
            : Number(durationMinutes),
          rating.trim(),
          Boolean(active),
          id
        ]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "Película no encontrada."
        });
      }

      res.json(formatMovie(result.rows[0]));
    } catch (error) {
      console.error(
        "Error actualizando película:",
        error
      );

      res.status(500).json({
        error: "No se pudo actualizar la película."
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

      const result = await pool.query(
        `
          DELETE FROM movies
          WHERE id = $1
          RETURNING id;
        `,
        [id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "Película no encontrada."
        });
      }

      res.json({
        success: true,
        message: "Película eliminada correctamente."
      });
    } catch (error) {
      console.error(
        "Error eliminando película:",
        error
      );

      res.status(500).json({
        error: "No se pudo eliminar la película."
      });
    }
  }
);

/*
==================================================
ADMINISTRACIÓN DE TANDAS
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
          m.title AS movie_title
        FROM showtimes s
        JOIN movies m ON m.id = s.movie_id
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
        price,
        active = true
      } = req.body;

      if (
        typeof movieId !== "string" ||
        !movieId.trim()
      ) {
        return res.status(400).json({
          error: "Debes seleccionar una película."
        });
      }

      if (
        typeof showDate !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(showDate)
      ) {
        return res.status(400).json({
          error: "La fecha de la tanda no es válida."
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

      const numericPrice = Number(price);

      if (
        !Number.isFinite(numericPrice) ||
        numericPrice < 0
      ) {
        return res.status(400).json({
          error: "El precio de la tanda no es válido."
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
          error: "La película seleccionada no existe."
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
            "Esta película ya tiene una tanda en esa fecha y hora."
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
            active
          )
          VALUES ($1, $2, $3, $4, $5, $6)
          RETURNING *;
        `,
        [
          id,
          movieId,
          showDate,
          showTime.trim(),
          numericPrice,
          Boolean(active)
        ]
      );

      const completeResult = await pool.query(
        `
          SELECT
            s.*,
            m.title AS movie_title
          FROM showtimes s
          JOIN movies m ON m.id = s.movie_id
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
        price,
        active = true
      } = req.body;

      if (
        typeof movieId !== "string" ||
        !movieId.trim()
      ) {
        return res.status(400).json({
          error: "Debes seleccionar una película."
        });
      }

      if (
        typeof showDate !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(showDate)
      ) {
        return res.status(400).json({
          error: "La fecha de la tanda no es válida."
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

      const numericPrice = Number(price);

      if (
        !Number.isFinite(numericPrice) ||
        numericPrice < 0
      ) {
        return res.status(400).json({
          error: "El precio de la tanda no es válido."
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
          error: "La película seleccionada no existe."
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
            "Ya existe otra tanda para esa película en esa fecha y hora."
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
          movieId,
          showDate,
          showTime.trim(),
          numericPrice,
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
            m.title AS movie_title
          FROM showtimes s
          JOIN movies m ON m.id = s.movie_id
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
CREAR RESERVACIÓN
==================================================
*/

app.post("/api/reservations", async (req, res) => {
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
        error: "Los asientos seleccionados no son válidos."
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
          s.active,
          m.title AS movie_title,
          m.active AS movie_active
        FROM showtimes s
        JOIN movies m ON m.id = s.movie_id
        WHERE s.id = $1
        FOR UPDATE;
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
        error: "Esta tanda no está disponible."
      });
    }

    const occupiedResult = await client.query(
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
        (seat) => occupiedSeats.has(seat)
      );

    if (unavailableSeats.length > 0) {
      await client.query("ROLLBACK");

      return res.status(409).json({
        error:
          "Uno o más asientos ya fueron reservados.",
        unavailableSeats
      });
    }

    const ticketId = crypto.randomUUID();
    const qrToken = crypto.randomBytes(32).toString("hex");
    const ticketPrice = Number(showtime.price);
    const total =
      ticketPrice * normalizedSeats.length;

    const storedCustomer = {
      ...customer,
      name: customerName,
      email: customerEmail,
      phone: customerPhone,
      showtimeId
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
          FALSE
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
        qrToken
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
      "Error creando la reservación:",
      error
    );

    res.status(500).json({
      error: "No se pudo crear la reservación."
    });
  } finally {
    client.release();
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
            error: "Reservación no encontrada."
          });
        }

        return res.status(400).json({
          error:
            "La reservación ya fue pagada o no puede procesarse."
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
VALIDAR CÓDIGO QR
==================================================
*/

app.get("/api/qr/:qr", async (req, res) => {
  try {
    const { qr } = req.params;

    const result = await pool.query(
      `
        SELECT *
        FROM tickets
        WHERE qr = $1;
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
      message: "Boleto válido.",
      ticket
    });
  } catch (error) {
    console.error(
      "Error validando el código QR:",
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
CHECK-IN DEL BOLETO
==================================================
*/

app.post(
  "/api/admin/checkin",
  requireAdmin,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const { qr } = req.body;

      if (
        typeof qr !== "string" ||
        !qr.trim()
      ) {
        return res.status(400).json({
          error: "El código QR es obligatorio."
        });
      }

      await client.query("BEGIN");

      const ticketResult = await client.query(
        `
          SELECT *
          FROM tickets
          WHERE qr = $1
          FOR UPDATE;
        `,
        [qr.trim()]
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

  res.status(500).json({
    error: "Ocurrió un error inesperado."
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
