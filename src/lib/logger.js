'use strict';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const configured = LEVELS[process.env.LOG_LEVEL] ?? LEVELS.info;

function log(level, msg, meta) {
  if (LEVELS[level] < configured) return;
  const entry = { ts: new Date().toISOString(), level, msg };
  if (meta !== undefined) entry.meta = meta;
  const line = JSON.stringify(entry);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

module.exports = {
  debug: (msg, meta) => log('debug', msg, meta),
  info: (msg, meta) => log('info', msg, meta),
  warn: (msg, meta) => log('warn', msg, meta),
  error: (msg, meta) => log('error', msg, meta),
};
