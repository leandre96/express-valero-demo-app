const { createLogger, format, transports } = require('winston');
const path = require('path');

// Definir el formato de los logs
const logFormat = format.printf(({ timestamp, level, message }) => {
  return `${timestamp} [${level.toUpperCase()}]: ${message}`;
});

// Crear el logger
const logger = createLogger({
  level: 'info', // niveles: error, warn, info, http, verbose, debug, silly
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.errors({ stack: true }), // captura stack trace en errores
    format.splat(),
    logFormat
  ),
  transports: [
    // Consola
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.simple()
      )
    }),

    // Archivo general
    new transports.File({
      filename: path.join(__dirname, 'logs', 'app.log'),
      level: 'info'
    }),

    // Archivo solo errores
    new transports.File({
      filename: path.join(__dirname, 'logs', 'error.log'),
      level: 'error'
    })
  ],
  exitOnError: false,
});

module.exports = logger;
