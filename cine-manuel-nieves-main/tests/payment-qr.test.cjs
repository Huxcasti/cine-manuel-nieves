// Contract regressions using the real route handlers and fixture-only services.
// These tests do not contact PostgreSQL, PayPal, Supabase or email providers.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const root = process.env.CINE_TEST_ROOT || path.join(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'backend/server.js'), 'utf8');
const showId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ticketId = '11111111-1111-4111-8111-111111111111';
const otherId = '22222222-2222-4222-8222-222222222222';
const canonical = value => String(value || '').trim().replace(/[{}-]/g, '').toLowerCase();

function ticket(overrides = {}) {
  return {
    id: ticketId, movie: 'Película de prueba', show_time: '2026-09-07 18:00',
    seats: ['B1'], total: '8.00',
    customer: { showtimeId: showId, paymentMethod: 'paypal', email: 'fixture@example.invalid' },
    payment_status: 'pending', qr: 'fixture-qr', manual_code: '12345', used: false,
    created_at: '2026-09-07T21:35:00Z', payment_hold_until: '2026-09-07T22:10:00Z',
    paypal_order_id: 'ORDER-A', cancellation_token_hash: crypto.createHash('sha256').update('cancel-fixture').digest('hex'),
    ...overrides
  };
}

function harness(initial = [ticket()]) {
  const h = {
    now: Date.parse('2026-09-07T21:40:00Z'), tickets: structuredClone(initial), scans: [],
    mails: [], queries: [], paypalCalls: [], signatureValid: true,
    showtimes: [{ id: showId, show_date: '2026-09-07', show_time: '18:00', active: true,
      movie_active: true, movie_title: 'Película de prueba', global_adult_price: '8.00',
      global_child_price: '6.00', global_senior_price: '5.00' }]
  };
  class Clock extends Date {
    constructor(...args) { super(...(args.length ? args : [h.now])); }
    static now() { return h.now; }
  }
  const rows = values => ({ rowCount: values.length, rows: structuredClone(values) });
  function active(t) {
    return ['paid', 'approved'].includes(t.payment_status) ||
      (t.payment_status === 'pending' && Date.parse(t.payment_hold_until ||
        new Date(Date.parse(t.created_at) + 300000).toISOString()) > h.now);
  }
  async function query(raw, args = []) {
    const q = raw.replace(/\s+/g, ' ').trim();
    h.queries.push(q);
    if (/^(BEGIN|COMMIT|ROLLBACK);?$/.test(q)) return rows([]);
    if (q.startsWith("SELECT customer->>'showtimeId' AS showtime_id"))
      return rows(h.tickets.filter(t => t.id === args[0]).map(t => ({ showtime_id: t.customer.showtimeId })));
    if (q.includes('FROM showtimes') && (q.includes('WHERE id = $1') || q.includes('WHERE s.id = $1')))
      return rows(h.showtimes.filter(s => canonical(s.id) === canonical(args[0])));
    if (q.startsWith('SELECT * FROM tickets WHERE qr ='))
      return rows(h.tickets.filter(t => t.qr === args[0] || t.manual_code === args[0]));
    if (q.startsWith('SELECT * FROM tickets WHERE id ='))
      return rows(h.tickets.filter(t => t.id === args[0]));
    if (q.startsWith('SELECT seats FROM tickets')) {
      const isConflict = q.includes('id <> $2');
      return rows(h.tickets.filter(t => {
        const sameShow = q.includes('TRANSLATE')
          ? canonical(t.customer.showtimeId) === canonical(args[0])
          : t.customer.showtimeId === args[0];
        return sameShow && active(t) && (!isConflict ||
          (t.id !== args[1] && t.seats.some(seat => args[2].includes(seat))));
      }).map(t => ({ seats: t.seats })));
    }
    if (q.startsWith('SELECT 1 FROM tickets WHERE manual_code ='))
      return rows(h.tickets.filter(t => t.manual_code === args[0]));
    if (q.startsWith('SELECT employee_name, scanned_at FROM checkins'))
      return rows(h.scans.filter(s => s.ticket_id === args[0]));
    if (q.startsWith('UPDATE tickets SET used = TRUE')) {
      const t = h.tickets.find(t => t.id === args[0]);
      t.used = true; t.checkin_at = new Clock().toISOString();
      return rows([t]);
    }
    if (q.startsWith('INSERT INTO checkins')) {
      h.scans.push({ id: args[0], ticket_id: args[1], employee_id: args[2], employee_name: args[3], employee_username: args[4], seats_count: args[5] });
      return rows([]);
    }
    if (q.startsWith('INSERT INTO tickets')) {
      const t = { id: args[0], movie: args[1], show_time: args[2], seats: args[3],
        total: args[4], customer: JSON.parse(args[5]), payment_status: args[6], qr: args[7],
        manual_code: args[8], cancellation_token_hash: args[9], ticket_breakdown: JSON.parse(args[10]),
        used: false, created_at: new Clock().toISOString() };
      h.tickets.push(t); return rows([t]);
    }
    if (/^UPDATE tickets SET payment_status = '(paid|payment_review|cancelled)'/.test(q)) {
      const t = h.tickets.find(t => t.id === args[0]);
      t.payment_status = q.match(/payment_status = '([^']+)'/)[1];
      if (args[1]) t.customer = JSON.parse(args[1]);
      if (q.includes('cancellation_token_hash = NULL')) t.cancellation_token_hash = null;
      t.payment_hold_until = null;
      return rows([t]);
    }
    if (q.startsWith('UPDATE tickets SET paypal_order_id =')) {
      const t = h.tickets.find(t => t.id === args[0]);
      t.paypal_order_id = args[1]; t.payment_hold_until = new Date(h.now + args[2] * 60000).toISOString();
      return rows([t]);
    }
    if (q.startsWith('DELETE FROM tickets WHERE id =')) {
      const removed = h.tickets.filter(t => t.id === args[0]);
      h.tickets = h.tickets.filter(t => t.id !== args[0]); return rows(removed);
    }
    if (/^DELETE FROM (employee_sessions|admin_sessions|admin_password_resets)/.test(q)) return rows([]);
    if (q.startsWith('DELETE FROM tickets WHERE')) {
      const removed = h.tickets.filter(t => t.payment_status === 'pending' &&
        (!t.paypal_order_id ? !active(t) : q.includes("INTERVAL '24 hours'") &&
          Date.parse(t.payment_hold_until || t.created_at) <= h.now - 86400000));
      h.tickets = h.tickets.filter(t => !removed.includes(t)); return rows(removed);
    }
    if (q.startsWith("UPDATE tickets SET payment_status = 'expired'")) {
      const changed = h.tickets.filter(t => t.payment_status === 'pending' && t.paypal_order_id &&
        Date.parse(t.payment_hold_until || t.created_at) <= h.now - 86400000);
      for (const t of changed) { t.payment_status = 'expired'; t.payment_hold_until = null; }
      return rows(changed);
    }
    throw new Error(`Unimplemented fixture SQL: ${q}`);
  }
  const pool = { query, async connect() {
    let before;
    return { async query(q, args) {
      if (q === 'BEGIN') before = structuredClone({ tickets: h.tickets, scans: h.scans });
      if (q === 'ROLLBACK' && before) { h.tickets = before.tickets; h.scans = before.scans; }
      return query(q, args);
    }, release() {} };
  } };
  const routes = new Map();
  const app = { set() {}, use() {}, listen() { throw new Error('No server startup in tests'); } };
  for (const method of ['get', 'post', 'put', 'delete'])
    app[method] = (route, ...handlers) => routes.set(`${method} ${route}`, handlers.at(-1));
  const noop = () => (_req, _res, next) => next();
  const express = () => app; express.json = noop;
  const multer = () => ({ single: noop }); multer.memoryStorage = () => ({}); multer.MulterError = class extends Error {};
  const deps = { express, cors: noop, crypto, pg: { Pool: function () { return pool; } }, multer,
    '@supabase/supabase-js': { createClient: () => ({}) }, resend: { Resend: class {} }, qrcode: {} };
  h.paypal = async (url, options) => {
    h.paypalCalls.push({ url, options });
    if (url.includes('verify-webhook')) return { verification_status: h.signatureValid ? 'SUCCESS' : 'FAILURE' };
    if (url.endsWith('/capture')) {
      const t = h.tickets.find(t => url.includes(t.paypal_order_id));
      return { status: 'COMPLETED', purchase_units: [{ custom_id: t.id, payments: { captures: [{
        id: 'CAPTURE-A', status: 'COMPLETED', amount: { value: Number(t.total).toFixed(2), currency_code: 'USD' }
      }] } }] };
    }
    if (url === '/v2/checkout/orders') return { id: 'ORDER-A' };
    throw new Error(`Unimplemented fixture PayPal request: ${url}`);
  };
  const context = vm.createContext({
    require: name => { if (!(name in deps)) throw new Error(`Unexpected import: ${name}`); return deps[name]; },
    process: { env: { DATABASE_URL: 'postgresql://fixture.invalid/review', ADMIN_KEY: 'fixture-only',
      SUPABASE_URL: 'https://fixture.invalid', SUPABASE_SERVICE_ROLE_KEY: 'fixture-only',
      PAYPAL_CLIENT_ID: 'fixture-only', PAYPAL_CLIENT_SECRET: 'fixture-only', PAYPAL_WEBHOOK_ID: 'fixture-only' },
      exit() { throw new Error('Unexpected exit'); } },
    Date: Clock, Buffer, URL, console: { log() {}, warn() {}, error() {} },
    fetch() { throw new Error('Network disabled'); }, setInterval() { throw new Error('Timers disabled'); },
    fixturePayPal: (...args) => h.paypal(...args),
    fixtureEmail: t => {
      h.mails.push(t.id);
      h.tickets.find(row => row.id === t.id).ticket_email_sent_at = new Clock().toISOString();
      return true;
    }
  });
  assert.match(source, /startServer\(\);\s*$/);
  vm.runInContext(source.replace(/startServer\(\);\s*$/, ''), context);
  vm.runInContext('paypalRequest = fixturePayPal; sendTicketEmailAndMark = fixtureEmail; cleanupOldQrFiles = async () => 0;', context);
  h.cleanup = () => vm.runInContext('cleanupPreviousBusinessDay()', context);
  h.invoke = async (method, route, body = {}, extra = {}) => {
    const res = { code: 200, body: null, status(n) { this.code = n; return this; }, json(x) { this.body = x; return this; } };
    await routes.get(`${method} ${route}`)({ body, params: { id: ticketId, orderId: 'ORDER-A' },
      headers: {}, query: {}, employee: { id: 'fixture-employee', name: 'Empleado', username: 'empleado' }, ...extra }, res);
    return res;
  };
  h.webhook = (resource = {}) => h.invoke('post', '/api/paypal/webhook', {
    event_type: 'PAYMENT.CAPTURE.COMPLETED', resource: { id: 'CAPTURE-A', custom_id: ticketId,
      supplementary_data: { related_ids: { order_id: 'ORDER-A' } },
      amount: { currency_code: 'USD', value: '8.00' }, ...resource }
  }, { headers: { 'paypal-transmission-id': 'fixture', 'paypal-transmission-time': 'fixture',
    'paypal-cert-url': 'https://fixture.invalid', 'paypal-auth-algo': 'fixture', 'paypal-transmission-sig': 'fixture' } });
  return h;
}

test('Client and server scripts parse', () => {
  new vm.Script(source);
  for (const file of ['index.html', 'admin.html', 'scanner.html']) {
    const html = fs.readFileSync(path.join(root, file), 'utf8');
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi))
      if (!/\bsrc\s*=/.test(m[1]) && !/application\//.test(m[1])) new vm.Script(m[2], { filename: file });
  }
});

for (const role of ['admin', 'employee']) {
  for (const [label, overrides, when, code] of [
    ['previous-day ticket', { show_time: '2026-09-06 18:00' }, '2026-09-07T21:40:00Z', 410],
    ['future ticket', { show_time: '2026-09-08 18:00' }, '2026-09-07T21:40:00Z', 409],
    ['21 minutes early', {}, '2026-09-07T21:39:00Z', 409],
    ['unpaid ticket', { payment_status: 'pending' }, '2026-09-07T21:40:00Z', 400],
    ['payment needing review', { payment_status: 'payment_review' }, '2026-09-07T21:40:00Z', 400],
    ['empty seats', { seats: [] }, '2026-09-07T21:40:00Z', 400]
  ]) test(`${role} rejects ${label} without consuming the ticket`, async () => {
    const h = harness([ticket({ payment_status: 'paid', ...overrides })]); h.now = Date.parse(when);
    const r = await h.invoke('post', `/api/${role}/checkin`, { qr: 'fixture-qr' });
    assert.equal(r.code, code, JSON.stringify(r.body));
    assert.equal(h.tickets[0].used, false); assert.equal(h.scans.length, 0);
  });
  test(`${role} accepts exactly 20 minutes early, records history and prevents second scan`, async () => {
    const h = harness([ticket({ payment_status: 'paid' })]);
    let r = await h.invoke('post', `/api/${role}/checkin`, { qr: 'fixture-qr' });
    assert.equal(r.code, 200, JSON.stringify(r.body)); assert.equal(h.tickets[0].used, true);
    assert.equal(h.scans.length, 1); assert.equal(h.scans[0].seats_count, 1);
    if (role === 'admin') assert.equal(h.scans[0].employee_name, 'Administrador');
    r = await h.invoke('post', `/api/${role}/checkin`, { qr: 'fixture-qr' });
    assert.equal(r.code, 409); assert.equal(h.scans.length, 1);
  });
}

test('Late payment for an already sold seat is retained for review, with no ticket email', async () => {
  const h = harness([ticket({ payment_hold_until: '2026-09-07T21:30:00Z' }),
    ticket({ id: otherId, payment_status: 'paid', qr: 'other', manual_code: '54321', paypal_order_id: 'ORDER-B' })]);
  const r = await h.webhook();
  assert.equal(r.code, 200); assert.equal(r.body.manualReview, true);
  assert.equal(h.tickets[0].payment_status, 'payment_review');
  assert.equal(h.tickets[0].customer.paypalCaptureId, 'CAPTURE-A');
  assert.equal(h.tickets.filter(t => t.payment_status === 'paid').length, 1);
  assert.equal(h.mails.length, 0);
  h.tickets.pop(); // Even if the other sale disappears, event replay stays in review.
  await h.webhook();
  assert.equal(h.tickets[0].payment_status, 'payment_review'); assert.equal(h.mails.length, 0);
});

test('An active pending reservation also protects its seat from a late payment', async () => {
  const h = harness([ticket({ payment_hold_until: '2026-09-07T21:30:00Z' }), ticket({ id: otherId })]);
  const r = await h.webhook(); assert.equal(r.body.manualReview, true); assert.equal(h.mails.length, 0);
});

test('Late confirmation can succeed when its seats are still available', async () => {
  const h = harness([ticket({ payment_hold_until: '2026-09-07T21:30:00Z' }),
    ticket({ id: otherId, payment_hold_until: '2026-09-07T21:20:00Z' })]);
  const r = await h.webhook(); assert.equal(r.body.reconciled, true);
  assert.equal(h.tickets[0].payment_status, 'paid'); assert.equal(h.mails.length, 1);
  await h.webhook(); assert.equal(h.mails.length, 1);
});

for (const status of ['refunded', 'reversed']) test(`Completed replay does not reactivate ${status} ticket`, async () => {
  const h = harness([ticket({ payment_status: status })]);
  await h.webhook(); assert.equal(h.tickets[0].payment_status, status); assert.equal(h.mails.length, 0);
});

for (const status of ['cancelled', 'expired']) test(`Completed payment after ${status} is retained for review`, async () => {
  const h = harness([ticket({ payment_status: status })]);
  await h.webhook(); assert.equal(h.tickets[0].payment_status, 'payment_review'); assert.equal(h.mails.length, 0);
});

test('Missing or rescheduled showtime does not generate a usable paid ticket', async () => {
  for (const absent of [true, false]) {
    const h = harness();
    if (absent) h.showtimes = []; else h.showtimes[0].show_time = '19:00';
    await h.webhook(); assert.equal(h.tickets[0].payment_status, 'payment_review'); assert.equal(h.mails.length, 0);
  }
});

test('Incorrect amount, order or signature cannot confirm a payment', async () => {
  for (const resource of [{ amount: { currency_code: 'USD', value: '0.01' } },
    { supplementary_data: { related_ids: { order_id: 'WRONG' } } }]) {
    const h = harness(); await h.webhook(resource);
    assert.equal(h.tickets[0].payment_status, 'pending'); assert.equal(h.mails.length, 0);
  }
  const h = harness(); h.signatureValid = false;
  assert.equal((await h.webhook()).code, 400); assert.equal(h.tickets[0].payment_status, 'pending');
});

test('Capture succeeds once and replay never starts another charge', async () => {
  const h = harness();
  for (let i = 0; i < 2; i++) {
    const r = await h.invoke('post', '/api/paypal/orders/:orderId/capture', { reservationId: ticketId });
    assert.equal(r.code, 200, JSON.stringify(r.body));
  }
  assert.equal(h.paypalCalls.filter(c => c.url.endsWith('/capture')).length, 1);
  assert.equal(h.tickets[0].payment_status, 'paid');
});

test('Capture refuses expired, conflicting or review reservations before contacting PayPal', async () => {
  for (const scenario of ['expired', 'conflict', 'review']) {
    const h = harness();
    if (scenario === 'expired') h.tickets[0].payment_hold_until = '2026-09-07T21:30:00Z';
    if (scenario === 'conflict') h.tickets.push(ticket({ id: otherId, payment_status: 'paid' }));
    if (scenario === 'review') h.tickets[0].payment_status = 'payment_review';
    const r = await h.invoke('post', '/api/paypal/orders/:orderId/capture', { reservationId: ticketId });
    assert.equal(r.code, 409, JSON.stringify(r.body)); assert.equal(h.paypalCalls.length, 0);
    if (scenario === 'review') assert.equal(r.body.code, 'PAYMENT_REVIEW_REQUIRED');
  }
});

test('Cancellation releases a PayPal reservation but retains its payment reference', async () => {
  const h = harness();
  const r = await h.invoke('delete', '/api/reservations/:id/cancel', {}, {
    headers: { 'x-reservation-cancel-token': 'cancel-fixture' }
  });
  assert.equal(r.code, 200); assert.equal(h.tickets.length, 1);
  assert.equal(h.tickets[0].payment_status, 'cancelled'); assert.equal(h.tickets[0].paypal_order_id, 'ORDER-A');
  const retry = await h.invoke('delete', '/api/reservations/:id/cancel', {}, {
    headers: { 'x-reservation-cancel-token': 'cancel-fixture' }
  });
  assert.equal(retry.code, 200); assert.equal(retry.body.released, true);
  await h.webhook(); assert.equal(h.tickets[0].payment_status, 'payment_review');
});

test('Cancellation still removes a reservation with no PayPal order', async () => {
  const h = harness([ticket({ paypal_order_id: null })]);
  const r = await h.invoke('delete', '/api/reservations/:id/cancel', {}, {
    headers: { 'x-reservation-cancel-token': 'cancel-fixture' }
  });
  assert.equal(r.code, 200); assert.equal(h.tickets.length, 0);
});

test('Cancellation requires the correct token', async () => {
  const h = harness();
  const r = await h.invoke('delete', '/api/reservations/:id/cancel', {}, {
    headers: { 'x-reservation-cancel-token': 'wrong' }
  });
  assert.equal(r.code, 403); assert.equal(h.tickets[0].payment_status, 'pending');
});

test('Cleanup retains old PayPal references while expiring the reservation', async () => {
  const h = harness([ticket({ payment_hold_until: '2026-09-05T21:30:00Z' })]);
  await h.cleanup(); assert.equal(h.tickets.length, 1);
  assert.equal(h.tickets[0].payment_status, 'expired'); assert.equal(h.tickets[0].paypal_order_id, 'ORDER-A');
});

test('Equivalent UUID representations cannot reserve the same seat twice', async () => {
  const h = harness([]);
  for (const [id, expected] of [[showId, 201], [showId.toUpperCase(), 409], [`{${showId}}`, 409]]) {
    const r = await h.invoke('post', '/api/reservations', { showtimeId: id, seats: ['B1'],
      ticketTypes: { adult: 1 }, paymentMethod: 'paypal', customer: { name: 'Fixture' } });
    assert.equal(r.code, expected, JSON.stringify(r.body));
  }
  assert.equal(h.tickets.length, 1);
});

test('Order setup, capture and webhook lock the showtime before locking its ticket', async () => {
  for (const kind of ['order', 'capture', 'webhook']) {
    const h = harness();
    if (kind === 'webhook') await h.webhook();
    else await h.invoke('post', kind === 'order' ? '/api/paypal/orders' : '/api/paypal/orders/:orderId/capture', { reservationId: ticketId });
    const show = h.queries.findIndex(q => q.includes('FROM showtimes') && q.includes('FOR UPDATE'));
    const row = h.queries.findIndex(q => q.startsWith('SELECT * FROM tickets') && q.includes('FOR UPDATE'));
    assert.ok(show >= 0 && row > show, `${kind}: consistent transaction lock order`);
  }
});
