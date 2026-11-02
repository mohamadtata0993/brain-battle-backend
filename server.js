'use strict';

require('dotenv').config();

const crypto = require('node:crypto');
const http = require('node:http');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');
const { createClient } = require('@supabase/supabase-js');

const PORT = Number.parseInt(process.env.PORT || '3001', 10);
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_INIT_DATA_MAX_AGE_SECONDS = Math.max(
  60,
  Number.parseInt(process.env.TELEGRAM_INIT_DATA_MAX_AGE_SECONDS || '86400', 10) || 86400,
);
const ROUND_TIME_MS = 30_000;
const ROUND_BREAK_MS = 3_000;
const COUNTDOWN_MS = 3_000;
const ROOM_TTL_MS = 30 * 60 * 1000;
const ROOM_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const ROOM_CODE_LENGTH = 6;
const TOTAL_ROUNDS = 5;

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const supabase = SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    })
  : null;

const configuredOrigins = (process.env.CORS_ORIGINS || process.env.FRONTEND_URL || 'http://localhost:5173,https://web.telegram.org')
  .split(',')
  .map((origin) => origin.trim().replace(/\/$/, ''))
  .filter(Boolean);

function originIsAllowed(origin) {
  if (!origin) return true; // native clients and same-origin health checks
  if (configuredOrigins.includes('*')) return true;
  return configuredOrigins.includes(origin.replace(/\/$/, ''));
}

const corsOptions = {
  origin(origin, callback) {
    if (originIsAllowed(origin)) return callback(null, true);
    return callback(new Error(`Origin is not allowed by CORS: ${origin}`));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true,
};

// Socket.IO accepts an origin array directly. Keep the Express CORS callback
// above for REST endpoints, and parse the Socket.IO allowlist independently.
const socketCorsOriginList = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map((origin) => origin.trim().replace(/\/$/, '')).filter(Boolean)
  : [];
const socketCorsOrigin = socketCorsOriginList.length > 0 ? socketCorsOriginList : '*';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors(corsOptions));
app.use(express.json({ limit: '16kb' }));
app.use(
  '/health',
  rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }),
);

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: socketCorsOrigin,
    methods: ['GET', 'POST'],
  },
  pingInterval: 25_000,
  pingTimeout: 20_000,
  maxHttpBufferSize: 16 * 1024,
});

// Room state is intentionally in memory. Deploy one backend instance unless a
// shared room store and Socket.IO adapter are added.
const rooms = new Map();
const socketToRoom = new Map();

app.get('/health', (_request, response) => {
  response.status(200).json({
    status: 'ok',
    service: 'brain-battle-api',
    databaseConfigured: Boolean(supabase),
    activeRooms: rooms.size,
    timestamp: new Date().toISOString(),
  });
});

app.use((_request, response) => {
  response.status(404).json({ error: 'Not found' });
});

app.use((error, _request, response, _next) => {
  if (error && /Origin is not allowed by CORS/.test(error.message || '')) {
    return response.status(403).json({ error: 'Origin is not allowed.' });
  }
  console.error('[http] request error:', error);
  return response.status(500).json({ error: 'Internal server error.' });
});

function verifyTelegramInitData(initData, botToken, maxAgeSeconds = TELEGRAM_INIT_DATA_MAX_AGE_SECONDS) {
  if (typeof initData !== 'string' || !initData || initData.length > 8_192 || !botToken) return null;

  try {
    const params = new URLSearchParams(initData);
    const providedHash = params.get('hash');
    if (!providedHash || !/^[a-f0-9]{64}$/i.test(providedHash)) return null;

    const authDate = Number(params.get('auth_date'));
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (!Number.isFinite(authDate) || authDate > nowSeconds + 60 || nowSeconds - authDate > maxAgeSeconds) {
      return null;
    }

    const dataCheckString = Array.from(params.entries())
      .filter(([key]) => key !== 'hash')
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
    const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest();
    const suppliedHash = Buffer.from(providedHash, 'hex');
    if (suppliedHash.length !== calculatedHash.length || !crypto.timingSafeEqual(suppliedHash, calculatedHash)) {
      return null;
    }

    const userJson = params.get('user');
    if (!userJson) return null;
    const user = JSON.parse(userJson);
    if (!user || (typeof user.id !== 'number' && typeof user.id !== 'string')) return null;
    return user;
  } catch (_error) {
    return null;
  }
}

io.use((socket, next) => {
  if (TELEGRAM_BOT_TOKEN) {
    const telegramUser = verifyTelegramInitData(
      socket.handshake.auth && socket.handshake.auth.initData,
      TELEGRAM_BOT_TOKEN,
    );
    if (!telegramUser) return next(new Error('Telegram authentication failed. Reopen the Mini App from Telegram.'));
    socket.data.telegramUser = telegramUser;
    return next();
  }

  if (IS_PRODUCTION) {
    return next(new Error('Telegram authentication is not configured on the server.'));
  }

  // Unsigned profile data is deliberately accepted only in local development.
  socket.data.telegramUser = null;
  return next();
});

function safeAck(acknowledgement, payload) {
  if (typeof acknowledgement !== 'function') return;
  try {
    acknowledgement(payload);
  } catch (error) {
    console.warn('[socket] acknowledgement could not be sent:', error.message);
  }
}

function fail(socket, acknowledgement, code, message, notify = false) {
  const payload = { ok: false, code, error: message };
  safeAck(acknowledgement, payload);
  if (notify && socket && socket.connected) socket.emit('server_error', payload);
  return payload;
}

function registerEvent(socket, eventName, handler) {
  socket.on(eventName, async (rawPayload, acknowledgement) => {
    const payload = rawPayload && typeof rawPayload === 'object' && !Array.isArray(rawPayload)
      ? rawPayload
      : {};
    try {
      await handler(payload, acknowledgement);
    } catch (error) {
      console.error(`[socket:${eventName}]`, error);
      fail(socket, acknowledgement, 'INTERNAL_ERROR', 'خطای موقت سرور رخ داد. دوباره تلاش کنید.', true);
    }
  });
}

function sanitizeName(value) {
  const normalized = String(value || '')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim();
  return Array.from(normalized || 'بازیکن').slice(0, 24).join('');
}

function safePhotoUrl(value) {
  if (typeof value !== 'string' || !value.trim()) return '';
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' ? parsed.toString() : '';
  } catch (_error) {
    return '';
  }
}

function profileForSocket(socket, payload) {
  const verifiedUser = socket.data.telegramUser;
  if (verifiedUser) {
    const fullName = [verifiedUser.first_name, verifiedUser.last_name].filter(Boolean).join(' ');
    return {
      name: sanitizeName(fullName || verifiedUser.username || 'بازیکن'),
      photoUrl: safePhotoUrl(verifiedUser.photo_url),
      telegramUserId: String(verifiedUser.id),
    };
  }
  return {
    name: sanitizeName(payload.name),
    photoUrl: safePhotoUrl(payload.photoUrl),
    telegramUserId: null,
  };
}

function generateRoomCode() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    let code = '';
    for (let index = 0; index < ROOM_CODE_LENGTH; index += 1) {
      code += ROOM_ALPHABET[crypto.randomInt(ROOM_ALPHABET.length)];
    }
    if (!rooms.has(code)) return code;
  }
  throw new Error('Could not allocate a unique room code.');
}

function createPlayer(socket, profile, id = crypto.randomUUID()) {
  return {
    id,
    socketId: socket.id,
    name: profile.name,
    photoUrl: profile.photoUrl,
    telegramUserId: profile.telegramUserId,
    score: 0,
    connected: true,
    readyForRematch: false,
  };
}

function publicPlayer(player, hostId) {
  return {
    id: player.id,
    name: player.name,
    photoUrl: player.photoUrl,
    score: player.score,
    connected: Boolean(player.connected),
    isHost: player.id === hostId,
    readyForRematch: Boolean(player.readyForRematch),
  };
}

function publicPlayers(room) {
  const hostId = room.players[0] ? room.players[0].id : null;
  return room.players.map((player) => publicPlayer(player, hostId));
}

function emitRoomUpdate(room) {
  io.to(room.roomCode).emit('room_update', {
    roomCode: room.roomCode,
    gameState: room.gameState,
    players: publicPlayers(room),
  });
}

function roomForSocket(socket) {
  const roomCode = socketToRoom.get(socket.id);
  return roomCode ? rooms.get(roomCode) || null : null;
}

function clearTimer(room, timerName) {
  if (room.timers[timerName]) {
    clearTimeout(room.timers[timerName]);
    room.timers[timerName] = null;
  }
}

function clearGameTimers(room) {
  clearTimer(room, 'countdown');
  clearTimer(room, 'round');
  clearTimer(room, 'next');
}

function clearRoom(room) {
  clearGameTimers(room);
  clearTimer(room, 'cleanup');
  for (const player of room.players) {
    if (!player.socketId) continue;
    if (socketToRoom.get(player.socketId) === room.roomCode) socketToRoom.delete(player.socketId);
    const onlineSocket = io.sockets.sockets.get(player.socketId);
    if (onlineSocket) {
      onlineSocket.leave(room.roomCode);
      onlineSocket.emit('room_closed', { roomCode: room.roomCode });
    }
  }
  rooms.delete(room.roomCode);
}

function scheduleRoomCleanup(room) {
  clearTimer(room, 'cleanup');
  room.timers.cleanup = setTimeout(() => {
    if (rooms.get(room.roomCode) !== room) return;
    clearRoom(room);
  }, ROOM_TTL_MS);
  room.timers.cleanup.unref?.();
}

function shuffle(values) {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const target = crypto.randomInt(index + 1);
    [result[index], result[target]] = [result[target], result[index]];
  }
  return result;
}

function isValidQuestion(question) {
  return Boolean(
    question
      && typeof question.text === 'string'
      && question.text.trim()
      && Array.isArray(question.options)
      && question.options.length === 4
      && question.options.every((option) => typeof option === 'string')
      && Number.isInteger(question.correct_option_index)
      && question.correct_option_index >= 0
      && question.correct_option_index <= 3,
  );
}

async function loadRandomQuestions(count) {
  if (!supabase) {
    throw new Error('Supabase is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.');
  }

  const { data, error } = await supabase
    .from('questions')
    .select('id, text, options, correct_option_index, category')
    .limit(1000);

  if (error) throw new Error(`Could not load questions: ${error.message}`);
  const validQuestions = (data || []).filter(isValidQuestion);
  if (validQuestions.length < count) {
    throw new Error(`At least ${count} valid questions are required; found ${validQuestions.length}.`);
  }
  return shuffle(validQuestions).slice(0, count);
}

function emitGameError(room, message) {
  io.to(room.roomCode).emit('game_error', {
    roomCode: room.roomCode,
    error: message,
  });
}

function beginCountdown(room) {
  if (room.gameState !== 'waiting' || room.players.length !== 2 || !room.players.every((player) => player.connected)) {
    return false;
  }

  clearTimer(room, 'cleanup');
  room.gameState = 'countdown';
  room.updatedAt = Date.now();
  const deadline = Date.now() + COUNTDOWN_MS;
  emitRoomUpdate(room);

  const tick = () => {
    if (rooms.get(room.roomCode) !== room || room.gameState !== 'countdown') return;
    const remainingMs = deadline - Date.now();
    const seconds = Math.max(0, Math.ceil(remainingMs / 1000));
    io.to(room.roomCode).emit('countdown', { roomCode: room.roomCode, seconds, totalSeconds: 3 });

    if (remainingMs <= 0) {
      room.timers.countdown = null;
      void startMatch(room);
      return;
    }
    room.timers.countdown = setTimeout(tick, Math.min(1_000, remainingMs));
    room.timers.countdown.unref?.();
  };

  tick();
  return true;
}

async function startMatch(room) {
  if (rooms.get(room.roomCode) !== room || room.gameState !== 'countdown') return;
  room.gameState = 'loading';
  io.to(room.roomCode).emit('game_loading', { roomCode: room.roomCode });

  try {
    const selectedQuestions = await loadRandomQuestions(TOTAL_ROUNDS);
    if (rooms.get(room.roomCode) !== room || room.gameState !== 'loading') return;
    if (room.players.length !== 2 || !room.players.every((player) => player.connected)) return;

    room.questions = selectedQuestions;
    room.roundIndex = 0;
    room.players.forEach((player) => {
      player.score = 0;
      player.readyForRematch = false;
    });
    room.matchSaved = false;
    room.matchSavePromise = null;
    room.gameOver = null;
    room.gameState = 'playing';
    io.to(room.roomCode).emit('game_started', {
      roomCode: room.roomCode,
      totalRounds: selectedQuestions.length,
    });
    emitRoomUpdate(room);
    sendQuestion(room);
  } catch (error) {
    console.error(`[game:${room.roomCode}] unable to start:`, error.message);
    if (rooms.get(room.roomCode) !== room || room.gameState !== 'loading') return;
    room.gameState = 'waiting';
    room.questions = [];
    room.roundIndex = -1;
    emitGameError(room, 'بازی شروع نشد. اتصال Supabase و وجود حداقل ۵ سؤال را بررسی کنید.');
    emitRoomUpdate(room);
  }
}

function sendQuestion(room) {
  const question = room.questions[room.roundIndex];
  if (!question) {
    finishGame(room, { reason: 'completed' });
    return;
  }

  room.gameState = 'playing';
  room.currentQuestion = question;
  room.roundAnswers = new Map();
  room.firstCorrectPlayerId = null;
  room.roundResolved = false;
  room.roundStartedAt = Date.now();
  room.roundDeadlineAt = room.roundStartedAt + ROUND_TIME_MS;

  // The answer key is deliberately omitted from this event.
  io.to(room.roomCode).emit('new_question', {
    roomCode: room.roomCode,
    round: room.roundIndex + 1,
    totalRounds: room.questions.length,
    questionId: question.id,
    text: question.text,
    options: question.options,
    category: question.category || 'عمومی',
    timeLimitMs: ROUND_TIME_MS,
    serverStartedAt: room.roundStartedAt,
    deadlineAt: room.roundDeadlineAt,
  });

  clearTimer(room, 'round');
  room.timers.round = setTimeout(() => finishRound(room, 'timeout'), ROUND_TIME_MS);
  room.timers.round.unref?.();
}

function finishRound(room, reason) {
  if (rooms.get(room.roomCode) !== room || room.gameState !== 'playing' || room.roundResolved) return;
  room.roundResolved = true;
  room.gameState = 'round_result';
  clearTimer(room, 'round');

  const question = room.currentQuestion;
  const answers = room.players.map((player) => {
    const answer = room.roundAnswers.get(player.id);
    return {
      playerId: player.id,
      optionIndex: answer ? answer.optionIndex : null,
      answeredAt: answer ? answer.answeredAt : null,
      isCorrect: Boolean(answer && answer.isCorrect),
      pointsAwarded: answer ? answer.pointsAwarded : 0,
    };
  });

  io.to(room.roomCode).emit('round_result', {
    roomCode: room.roomCode,
    round: room.roundIndex + 1,
    correctOptionIndex: question.correct_option_index,
    correctAnswer: question.options[question.correct_option_index],
    answers,
    players: publicPlayers(room),
    reason,
  });

  clearTimer(room, 'next');
  room.timers.next = setTimeout(() => {
    room.timers.next = null;
    if (rooms.get(room.roomCode) !== room || room.gameState !== 'round_result') return;
    if (room.roundIndex + 1 >= room.questions.length) {
      finishGame(room, { reason: 'completed' });
      return;
    }
    room.roundIndex += 1;
    sendQuestion(room);
  }, ROUND_BREAK_MS);
  room.timers.next.unref?.();
}

async function persistMatch(room, result) {
  if (room.matchSaved || room.matchSavePromise) return room.matchSavePromise;
  room.matchSaved = true;
  if (!supabase) {
    console.error(`[game:${room.roomCode}] match was not persisted: Supabase is not configured.`);
    return null;
  }

  const player1 = room.players[0];
  const player2 = room.players[1];
  const row = {
    player1_name: player1 ? player1.name : 'بازیکن ۱',
    player2_name: player2 ? player2.name : 'بازیکن ۲',
    winner_name: result.winnerName,
    player1_score: player1 ? player1.score : 0,
    player2_score: player2 ? player2.score : 0,
  };

  room.matchSavePromise = (async () => {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        const { error } = await supabase.from('matches').insert(row);
        if (!error) return true;
        throw error;
      } catch (error) {
        console.error(`[game:${room.roomCode}] match save attempt ${attempt + 1} failed:`, error.message);
        if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 400 * (2 ** attempt)));
      }
    }
    return false;
  })();

  return room.matchSavePromise;
}

function finishGame(room, { winnerPlayerId = null, reason = 'completed' } = {}) {
  if (rooms.get(room.roomCode) !== room || room.gameState === 'finished') return;
  clearGameTimers(room);
  room.gameState = 'finished';
  room.updatedAt = Date.now();

  const player1 = room.players[0] || null;
  const player2 = room.players[1] || null;
  let winner = winnerPlayerId ? room.players.find((player) => player.id === winnerPlayerId) || null : null;
  if (!winner && reason === 'completed' && player1 && player2 && player1.score !== player2.score) {
    winner = player1.score > player2.score ? player1 : player2;
  }
  const isDraw = reason === 'completed' && Boolean(player1 && player2 && player1.score === player2.score);
  const winnerName = winner ? winner.name : (isDraw ? 'مساوی' : 'بدون برنده');

  const result = {
    roomCode: room.roomCode,
    reason,
    winnerName,
    winnerPlayerId: winner ? winner.id : null,
    isDraw,
    player1Name: player1 ? player1.name : 'بازیکن ۱',
    player2Name: player2 ? player2.name : 'بازیکن ۲',
    player1Score: player1 ? player1.score : 0,
    player2Score: player2 ? player2.score : 0,
    players: publicPlayers(room),
  };

  room.gameOver = result;
  io.to(room.roomCode).emit('game_over', result);
  emitRoomUpdate(room);
  void persistMatch(room, result);
  scheduleRoomCleanup(room);
}

function handleDisconnect(socket, reason) {
  const roomCode = socketToRoom.get(socket.id);
  if (!roomCode) return;
  socketToRoom.delete(socket.id);
  const room = rooms.get(roomCode);
  if (!room) return;

  const player = room.players.find((candidate) => candidate.socketId === socket.id);
  if (!player) return;
  player.connected = false;
  player.socketId = null;
  player.readyForRematch = false;

  const activeStates = new Set(['countdown', 'loading', 'playing', 'round_result']);
  if (activeStates.has(room.gameState)) {
    const remainingPlayer = room.players.find((candidate) => candidate.connected);
    io.to(room.roomCode).emit('opponent_disconnected', {
      roomCode: room.roomCode,
      playerId: player.id,
      playerName: player.name,
      reason,
    });
    finishGame(room, {
      winnerPlayerId: remainingPlayer ? remainingPlayer.id : null,
      reason: 'disconnect',
    });
    return;
  }

  if (room.gameState === 'waiting') {
    room.players = room.players.filter((candidate) => candidate.id !== player.id);
    io.to(room.roomCode).emit('opponent_left', {
      roomCode: room.roomCode,
      playerName: player.name,
    });
    if (room.players.length === 0) {
      clearRoom(room);
      return;
    }
    emitRoomUpdate(room);
    return;
  }

  // Keep the finished match and its player scores for the result screen, but
  // reject a rematch until both players are connected again.
  io.to(room.roomCode).emit('room_update', {
    roomCode: room.roomCode,
    gameState: room.gameState,
    players: publicPlayers(room),
  });
}

io.on('connection', (socket) => {
  console.info(`[socket] connected ${socket.id}`);

  registerEvent(socket, 'create_room', (payload, acknowledgement) => {
    if (socketToRoom.has(socket.id)) {
      return fail(socket, acknowledgement, 'ALREADY_IN_ROOM', 'ابتدا بازی فعلی را تمام کنید.');
    }

    const profile = profileForSocket(socket, payload);
    const roomCode = generateRoomCode();
    const player = createPlayer(socket, profile);
    const room = {
      roomCode,
      players: [player],
      gameState: 'waiting',
      questions: [],
      roundIndex: -1,
      currentQuestion: null,
      roundStartedAt: null,
      roundDeadlineAt: null,
      roundAnswers: new Map(),
      firstCorrectPlayerId: null,
      roundResolved: false,
      timers: { countdown: null, round: null, next: null, cleanup: null },
      matchSaved: false,
      matchSavePromise: null,
      gameOver: null,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    rooms.set(roomCode, room);
    socket.join(roomCode);
    socketToRoom.set(socket.id, roomCode);
    safeAck(acknowledgement, {
      ok: true,
      roomCode,
      playerId: player.id,
      gameState: room.gameState,
      players: publicPlayers(room),
    });
    emitRoomUpdate(room);
  });

  registerEvent(socket, 'join_room', (payload, acknowledgement) => {
    if (socketToRoom.has(socket.id)) {
      return fail(socket, acknowledgement, 'ALREADY_IN_ROOM', 'ابتدا از اتاق فعلی خارج شوید.');
    }

    const roomCode = String(payload.roomCode || '').trim().toUpperCase();
    if (!/^[A-Z0-9]{6}$/.test(roomCode)) {
      return fail(socket, acknowledgement, 'INVALID_ROOM_CODE', 'کد اتاق باید ۶ حرف یا عدد انگلیسی باشد.');
    }

    const room = rooms.get(roomCode);
    if (!room) return fail(socket, acknowledgement, 'ROOM_NOT_FOUND', 'اتاق پیدا نشد یا منقضی شده است.');
    if (room.gameState !== 'waiting') return fail(socket, acknowledgement, 'ROOM_ALREADY_STARTED', 'بازی این اتاق شروع شده است.');
    if (room.players.length >= 2) return fail(socket, acknowledgement, 'ROOM_FULL', 'این اتاق پر است.');

    const player = createPlayer(socket, profileForSocket(socket, payload));
    room.players.push(player);
    room.updatedAt = Date.now();
    socket.join(room.roomCode);
    socketToRoom.set(socket.id, room.roomCode);

    safeAck(acknowledgement, {
      ok: true,
      roomCode: room.roomCode,
      playerId: player.id,
      gameState: room.gameState,
      players: publicPlayers(room),
    });
    emitRoomUpdate(room);

    if (room.players.length === 2) {
      io.to(room.roomCode).emit('game_ready', {
        roomCode: room.roomCode,
        players: publicPlayers(room),
      });
      beginCountdown(room);
    }
  });

  registerEvent(socket, 'start_game', (_payload, acknowledgement) => {
    const room = roomForSocket(socket);
    if (!room) return fail(socket, acknowledgement, 'NOT_IN_ROOM', 'ابتدا وارد یک اتاق شوید.');
    if (room.players.length !== 2 || !room.players.every((player) => player.connected)) {
      return fail(socket, acknowledgement, 'WAITING_FOR_PLAYER', 'هنوز هر دو بازیکن وارد اتاق نشده‌اند.');
    }
    if (room.gameState === 'waiting') beginCountdown(room);
    safeAck(acknowledgement, { ok: true, gameState: room.gameState });
  });

  registerEvent(socket, 'submit_answer', (payload, acknowledgement) => {
    const room = roomForSocket(socket);
    if (!room) return fail(socket, acknowledgement, 'NOT_IN_ROOM', 'اتاق بازی پیدا نشد.');
    if (room.gameState !== 'playing' || !room.currentQuestion) {
      return fail(socket, acknowledgement, 'ROUND_NOT_ACTIVE', 'این سؤال دیگر فعال نیست.');
    }

    const player = room.players.find((candidate) => candidate.socketId === socket.id && candidate.connected);
    if (!player) return fail(socket, acknowledgement, 'PLAYER_NOT_FOUND', 'بازیکن در این اتاق پیدا نشد.');

    const optionIndex = Number(payload.optionIndex);
    if (!Number.isInteger(optionIndex) || optionIndex < 0 || optionIndex > 3) {
      return fail(socket, acknowledgement, 'INVALID_ANSWER', 'گزینهٔ انتخاب‌شده معتبر نیست.');
    }

    const serverReceivedAt = Date.now();
    if (serverReceivedAt >= room.roundDeadlineAt) {
      finishRound(room, 'timeout');
      return fail(socket, acknowledgement, 'ROUND_EXPIRED', 'زمان پاسخ‌گویی تمام شده است.');
    }
    if (room.roundAnswers.has(player.id)) {
      return fail(socket, acknowledgement, 'ALREADY_ANSWERED', 'پاسخ شما برای این سؤال ثبت شده است.');
    }

    const isCorrect = optionIndex === room.currentQuestion.correct_option_index;
    let pointsAwarded = 0;
    if (isCorrect && room.firstCorrectPlayerId === null) {
      room.firstCorrectPlayerId = player.id;
      player.score += 10;
      pointsAwarded = 10;
    }

    const answer = {
      optionIndex,
      answeredAt: serverReceivedAt,
      isCorrect,
      pointsAwarded,
    };
    room.roundAnswers.set(player.id, answer);

    const feedback = {
      ok: true,
      correct: isCorrect,
      pointsAwarded,
      answeredAt: serverReceivedAt,
      message: isCorrect
        ? (pointsAwarded > 0 ? 'پاسخ درست بود و ۱۰ امتیاز گرفتید.' : 'پاسخ درست بود، اما امتیاز به پاسخ سریع‌تر رسید.')
        : 'پاسخ ثبت شد؛ حریف هنوز فرصت پاسخ دارد.',
    };
    socket.emit('answer_feedback', feedback);
    safeAck(acknowledgement, feedback);

    if (pointsAwarded > 0) {
      io.to(room.roomCode).emit('score_update', {
        roomCode: room.roomCode,
        round: room.roundIndex + 1,
        players: publicPlayers(room),
      });
    }

    if (room.roundAnswers.size >= 2) finishRound(room, 'both_answered');
  });

  registerEvent(socket, 'play_again', (_payload, acknowledgement) => {
    const room = roomForSocket(socket);
    if (!room) return fail(socket, acknowledgement, 'NOT_IN_ROOM', 'اتاق بازی پیدا نشد.');
    if (room.gameState !== 'finished') {
      return fail(socket, acknowledgement, 'GAME_NOT_FINISHED', 'بازی هنوز تمام نشده است.');
    }
    if (room.players.length !== 2 || !room.players.every((player) => player.connected)) {
      return fail(socket, acknowledgement, 'OPPONENT_OFFLINE', 'برای بازی مجدد باید هر دو بازیکن آنلاین باشند.');
    }

    const player = room.players.find((candidate) => candidate.socketId === socket.id);
    if (!player) return fail(socket, acknowledgement, 'PLAYER_NOT_FOUND', 'بازیکن در این اتاق پیدا نشد.');
    player.readyForRematch = true;

    const readiness = room.players.map((candidate) => ({
      playerId: candidate.id,
      ready: candidate.readyForRematch,
    }));
    io.to(room.roomCode).emit('rematch_status', {
      roomCode: room.roomCode,
      players: readiness,
    });

    const bothReady = room.players.every((candidate) => candidate.readyForRematch && candidate.connected);
    safeAck(acknowledgement, { ok: true, waitingForOpponent: !bothReady });

    if (bothReady) {
      clearTimer(room, 'cleanup');
      room.gameState = 'waiting';
      room.questions = [];
      room.roundIndex = -1;
      room.currentQuestion = null;
      room.roundAnswers = new Map();
      room.gameOver = null;
      room.matchSaved = false;
      room.matchSavePromise = null;
      room.players.forEach((candidate) => {
        candidate.score = 0;
        candidate.readyForRematch = false;
      });
      io.to(room.roomCode).emit('rematch_started', { roomCode: room.roomCode });
      emitRoomUpdate(room);
      beginCountdown(room);
    }
  });

  socket.on('disconnect', (reason) => {
    console.info(`[socket] disconnected ${socket.id}: ${reason}`);
    handleDisconnect(socket, reason);
  });
});

if (!supabase) {
  console.warn('[startup] Supabase is not configured. Rooms can be created, but matches cannot start.');
}
if (IS_PRODUCTION && !TELEGRAM_BOT_TOKEN) {
  console.error('[startup] TELEGRAM_BOT_TOKEN is required in production; socket connections will be rejected.');
}

if (require.main === module) {
  server.listen(PORT, '0.0.0.0', () => {
    console.info(`[startup] Brain Battle backend listening on 0.0.0.0:${PORT} (${NODE_ENV})`);
    console.info(`[startup] Express CORS allowlist: ${configuredOrigins.join(', ') || '(none)'}`);
    console.info(`[startup] Socket.IO CORS origin: ${Array.isArray(socketCorsOrigin) ? socketCorsOrigin.join(', ') : socketCorsOrigin}`);
  });

  const shutdown = (signal) => {
    console.info(`[shutdown] received ${signal}`);
    for (const room of rooms.values()) clearGameTimers(room);
    io.close(() => {
      server.close(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 10_000).unref?.();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

module.exports = {
  app,
  server,
  io,
  rooms,
  verifyTelegramInitData,
  loadRandomQuestions,
};
