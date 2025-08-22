const express = require('express');
const crypto = require('crypto');
const pool = require('./db');
const logger = require('./logger');
require('dotenv').config();

const app = express();

// 1) Conservar el body crudo para el HMAC
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf; // Buffer
  }
}));

// 2) Helper: comparación tiempo-constante
function safeEqual(a, b) {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// 3) Middleware para verificar firma HMAC-SHA256
function verifyWebhookSignature(req, res, next) {
  try {
    const secret = process.env.WEBHOOK_SECRET;
    if (!secret) {
      logger.error('WEBHOOK_SECRET no configurado');
      return res.status(500).json({ success: false, message: 'Server misconfigured' });
    }

    // Encabezados esperados (ajústalos si el emisor usa otros)
    const signature = req.get('X-Signature');               // hex del HMAC
    const timestamp = req.get('X-Signature-Timestamp');     // epoch (segundos o ms)

    if (!signature || !timestamp) {
      return res.status(400).json({ success: false, message: 'Missing signature headers' });
    }

    // 3.1) Protección anti-replay (5 minutos)
    const now = Date.now();
    const tsMs = String(timestamp).length > 10 ? Number(timestamp) : Number(timestamp) * 1000;
    if (Number.isNaN(tsMs)) {
      return res.status(400).json({ success: false, message: 'Invalid timestamp' });
    }
    const ageMs = Math.abs(now - tsMs);
    if (ageMs > 5 * 60 * 1000) { // > 5 minutos
      return res.status(408).json({ success: false, message: 'Stale timestamp' });
    }

    // 3.2) Payload para firmar: "<timestamp>.<rawBody>"
    const signedPayload = `${timestamp}.${req.rawBody}`;

    // 3.3) Recalcular HMAC
    const expected = crypto
      .createHmac('sha256', secret)
      .update(signedPayload)
      .digest('hex');

    // 3.4) Comparación tiempo-constante
    if (!safeEqual(expected, signature)) {
      logger.warn('Firma inválida');
      return res.status(401).json({ success: false, message: 'Invalid signature' });
    }

    // OK
    next();
  } catch (err) {
    logger.error(`Error verificando firma: ${err.message}`);
    return res.status(400).json({ success: false, message: 'Bad request' });
  }
}

app.post('/webHookEcuasigad', verifyWebhookSignature, async (req, res) => {
  try {
    const dto = req.body;
    const tramite = dto.Tramite;

    const now = new Date();

    const query = `
  INSERT INTO "Procedures" (
    external_id, procedure_number, order_number, arrives_date, endorsement_date,
    authorized_out_date, approval_sent_date, warehouse_exit_date, procedure_end_date,
    creation_date, approval_date, transmition_date, channel, merchant, status,
    last_comment, type, "createdAt", "updatedAt", liquidation_pay_date, email_payment_sent
  )
  VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21
  )
  ON CONFLICT (procedure_number) DO UPDATE
  SET
    external_id = EXCLUDED.external_id,
    order_number = EXCLUDED.order_number,
    arrives_date = EXCLUDED.arrives_date,
    endorsement_date = EXCLUDED.endorsement_date,
    authorized_out_date = EXCLUDED.authorized_out_date,
    approval_sent_date = EXCLUDED.approval_sent_date,
    warehouse_exit_date = EXCLUDED.warehouse_exit_date,
    procedure_end_date = EXCLUDED.procedure_end_date,
    creation_date = EXCLUDED.creation_date,
    approval_date = EXCLUDED.approval_date,
    transmition_date = EXCLUDED.transmition_date,
    channel = EXCLUDED.channel,
    merchant = EXCLUDED.merchant,
    status = EXCLUDED.status,
    last_comment = EXCLUDED.last_comment,
    type = EXCLUDED.type,
    "updatedAt" = EXCLUDED."updatedAt",
    liquidation_pay_date = EXCLUDED.liquidation_pay_date,
    email_payment_sent = EXCLUDED.email_payment_sent
`;


    const values = [
      dto.CodigoEvento,
      tramite.NumeroTramite,
      tramite.NumeroPedido,
      tramite.FechaLLegada,
      tramite.FechaEndoso || null,
      tramite.FechaAutorizadoSalida || null,
      tramite.FechaEnvioAprobacion || null,
      tramite.FechaSalidaBodega || null,
      tramite.FechaFinTramite || null,
      tramite.FechaCreacion || null,
      tramite.FechaAprobacion || null,
      tramite.FechaTransmision || null,
      tramite.Regimen?.Nombre || null,
      tramite.Cliente?.Nombre || null,
      tramite.EstadoTramite || null,
      dto.DescripcionEvento || null,
      tramite.TipoTramite || null,
      now,
      now,
      tramite.FechaPagoLiquidacion || null,
      tramite.EmailPagoEnviado || false
    ];

    await pool.query(query, values);
    logger.info(`✅ Webhook OK: Trámite ${tramite.NumeroTramite}`);
    res.status(200).json({ success: true, message: 'Procedimiento registrado correctamente' });
  } catch (error) {
    logger.error(`❌ Error procesando webhook: ${error.message}`);
    res.status(500).json({ success: false, message: 'Error procesando webhook' });
  }
});

app.listen(process.env.PORT, () => {
  logger.info(`🚀 Servidor escuchando en el puerto ${process.env.PORT}`);
});
