# Corrección de pagos y validación QR

Versión preparada el 7 de septiembre de 2026 a partir del ZIP enviado.

## Qué se corrigió

- Las reservas, la creación de órdenes, la captura de pagos y la confirmación
  por webhook coordinan sus cambios con el mismo bloqueo de la tanda. El orden
  es siempre tanda y después boleto. Antes de cobrar o confirmar una entrada se
  vuelve a comprobar la disponibilidad del asiento.
- Si PayPal confirma un pago cuyos asientos pertenecen a otra reserva activa,
  se conserva el pago como `payment_review`. El boleto no queda habilitado ni
  se envía el correo normal de entrada confirmada.
- El administrador verá **Pago recibido: revisar**, el motivo, la referencia
  de la reserva y el identificador de captura de PayPal. Esa fila necesita
  atención del personal del cine; esta corrección no ejecuta reembolsos ni
  reasignaciones automáticamente. Estos importes no se cuentan como entradas
  vendidas en los indicadores que suman únicamente boletos habilitados.
- Una notificación tardía puede confirmar una reserva pendiente si sus asientos
  siguen disponibles y la tanda conserva su fecha y hora. Si la reserva fue
  cancelada o cerrada, el pago se conserva para revisión.
- Las reservas con orden de PayPal conservan su referencia al cancelarse o
  cerrarse por antigüedad. Sus asientos se liberan, pero el registro permite
  relacionar una notificación posterior con el pago correspondiente.
- Repetir una notificación no reactiva entradas reembolsadas, revertidas o en
  revisión. Las llamadas a PayPal tienen un tiempo máximo de 20 segundos por
  petición para limitar cuánto tiempo pueden mantener ocupados los bloqueos.
- Los identificadores equivalentes de una tanda se comparan de forma uniforme
  para que mayúsculas o llaves no creen grupos separados de asientos.
- La validación del administrador aplica la misma fecha y ventana de 20
  minutos previos que el empleado. También agrega el registro de entrada al
  historial, identificado como **Administrador**.

## Archivos del cambio

| Archivo | Cambio |
| --- | --- |
| `backend/server.js` | Reservas, pagos, conservación de referencias y validación administrativa |
| `admin.html` | Estado de revisión, referencias del pago y validez de la entrada |
| `index.html` | Mensaje específico de pago en revisión y prevención de nuevo intento en esa pantalla |
| `package.json` | Comando de pruebas |
| `tests/payment-qr.test.cjs` | Pruebas locales de regresión |

El ZIP también contiene las imágenes y los demás archivos del proyecto.

## Validación realizada

Ejecutar desde la carpeta del proyecto con Node.js 24:

```sh
npm test
```

Las 32 pruebas locales pasan. Ejecutan los manejadores del servidor con
sustitutos de la base de datos, PayPal y correo, y comprueban la sintaxis de los
tres HTML y el servidor. Incluyen el pago tardío sobre un asiento ya vendido,
reservas activas, cancelación repetida, confirmaciones repetidas, importes
incorrectos, conservación de referencias, límites de horario y segundo escaneo.

Las dos regresiones principales también se ejecutaron sobre el código original:
fallaron allí y pasan con la corrección.

Estas pruebas no abren conexiones, no realizan cobros ni envían correos. No
verifican PostgreSQL real, concurrencia entre conexiones reales, sesiones de
usuario, cámara del teléfono ni la entrega real del correo.

## Próximo paso: comprobar en pruebas antes de publicar

1. Descomprimir el ZIP. La carpeta interior contiene la raíz del proyecto.
2. Preparar estos cambios en una rama de prueba del repositorio, conservando
   las rutas de la tabla anterior. El archivo ZIP por sí solo no sustituye
   los archivos de la web.
3. Usar una base de datos de prueba y PayPal Sandbox. Confirmar la configuración
   de PayPal, su webhook y el correo en ese entorno.
4. Completar una compra de prueba: asiento, pago, correo y validación QR.
5. Verificar con dos sesiones la competencia por el mismo asiento y un pago
   cuya confirmación llegue tarde. Comprobar también cancelar, volver a intentar
   y consultar el historial del administrador.
6. Publicar los archivos del cambio después de completar esas comprobaciones.

El código preparado todavía no se ha publicado en GitHub ni desplegado en
Render. La corrección no puede recuperar reservas que una versión anterior
ya borró, ni arregla automáticamente ventas duplicadas que ya existan.

## Referencias técnicas

- [Bloqueos y transacciones de PostgreSQL](https://www.postgresql.org/docs/current/explicit-locking.html)
- [Eventos de webhook de PayPal](https://developer.paypal.com/api/rest/webhooks/event-names/)
