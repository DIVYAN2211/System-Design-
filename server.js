require('dotenv').config();

const express = require('express'); 
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
});

// Basic middleware
app.use(cors());
app.use(express.json());

// Serve static frontend from /public
const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));

// Uploads directory for images
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
app.use('/uploads', express.static(uploadsDir));

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname) || '';
      const base = path.basename(file.originalname, ext).replace(/\s+/g, '-');
      cb(null, `${Date.now()}-${base}${ext}`);
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
});

// Document upload configuration (for HLD, LLD, Requirements)
const documentUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname) || '';
      const base = path.basename(file.originalname, ext).replace(/\s+/g, '-');
      cb(null, `doc-${Date.now()}-${base}${ext}`);
    },
  }),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit for documents
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'text/plain',
      'application/rtf',
    ];
    const allowedExts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.rtf'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(file.mimetype) || allowedExts.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Allowed: PDF, DOC, DOCX, XLS, XLSX, TXT, RTF'));
    }
  },
});

// MongoDB connection
const mongoUri = process.env.MONGODB_URI || '';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

// Schemas
const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    lastSeen: { type: Date },
    bio: { type: String, default: '' },
    avatarUrl: { type: String, default: '' },
  },
  { timestamps: true }
);

const chatSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    type: { type: String, enum: ['group', 'direct'], default: 'group' },
    participants: [{ type: String }],
    lastMessageAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const messageSchema = new mongoose.Schema(
  {
    chatId: { type: mongoose.Schema.Types.ObjectId, ref: 'Chat', required: true },
    sender: { type: String, required: true },
    text: { type: String },
    imageUrl: { type: String },
    readBy: [{ type: String }],
  },
  { timestamps: true }
);

const documentationSchema = new mongoose.Schema(
  {
    filename: { type: String, required: true },
    originalName: { type: String, required: true },
    fileUrl: { type: String, required: true },
    fileSize: { type: Number, required: true },
    mimeType: { type: String, required: true },
    documentType: { type: String, enum: ['HLD', 'LLD', 'Requirements'], required: true },
    uploadedBy: { type: String, required: true },
    description: { type: String, default: '' },
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);
const Chat = mongoose.model('Chat', chatSchema);
const Message = mongoose.model('Message', messageSchema);
const Documentation = mongoose.model('Documentation', documentationSchema);

let memoryMode = false;
let memChats = [];
let memMessages = [];
let memDocumentation = [];

async function connectMongo() {
  if (!mongoUri) {
    console.warn(
      'MONGODB_URI not set. Messages will not be persisted. Set it in .env to enable Atlas storage.'
    );
    memoryMode = true;
    return;
  }
  try {
    await mongoose.connect(mongoUri);
    console.log('Connected to MongoDB Atlas');
  } catch (err) {
    console.error('Failed to connect to MongoDB:', err.message);
    memoryMode = true;
  }
}

const onlineUsers = new Map(); // username -> count
const userSockets = new Map(); // username -> Set<socketId>

function makeToken(user) {
  return jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function ensureDefaultChat(username) {
  if (memoryMode) {
    if (!memChats.length) {
      memChats.push({ _id: 'general', name: 'General', type: 'group', participants: [username] });
    } else if (!memChats[0].participants.includes(username)) {
      memChats[0].participants.push(username);
    }
    return memChats[0];
  }
  let chat = await Chat.findOne({ name: 'General' });
  if (!chat) {
    chat = await Chat.create({ name: 'General', type: 'group', participants: [username] });
  } else if (!chat.participants.includes(username)) {
    chat.participants.push(username);
    await chat.save();
  }
  return chat;
}

async function chatsForUser(username) {
  if (memoryMode) {
    return memChats.filter((c) => c.participants.includes(username));
  }
  return Chat.find({ participants: username }).sort({ lastMessageAt: -1 }).lean();
}

async function latestMessages(chatId, limit = 100) {
  if (memoryMode) {
    return memMessages.filter((m) => m.chatId === chatId).slice(-limit);
  }
  return Message.find({ chatId }).sort({ createdAt: -1 }).limit(limit).lean();
}

// Auth routes
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
    if (!memoryMode) {
      const exists = await User.findOne({ username });
      if (exists) return res.status(400).json({ error: 'User exists' });
      const passwordHash = await bcrypt.hash(password, 10);
      const user = await User.create({ username, passwordHash });
      await ensureDefaultChat(username);
      const token = makeToken(user);
      return res.json({ token, user: { username, bio: user.bio, avatarUrl: user.avatarUrl } });
    } else {
      const user = { username, password };
      memChats = memChats.map((c) =>
        c.name === 'General' && !c.participants.includes(username)
          ? { ...c, participants: [...c.participants, username] }
          : c
      );
      const token = makeToken(user);
      return res.json({ token, user: { username, bio: '', avatarUrl: '' } });
    }
  } catch (err) {
    console.error('register error', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
    if (!memoryMode) {
      const user = await User.findOne({ username });
      if (!user) return res.status(400).json({ error: 'Invalid credentials' });
      const ok = await bcrypt.compare(password, user.passwordHash);
      if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
      await ensureDefaultChat(username);
      const token = makeToken(user);
      return res.json({ token, user: { username, bio: user.bio, avatarUrl: user.avatarUrl } });
    }
    const token = makeToken({ username });
    return res.json({ token, user: { username, bio: '', avatarUrl: '' } });
  } catch (err) {
    console.error('login error', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Create group chat
app.post('/api/chats', authMiddleware, async (req, res) => {
  try {
    const { name, participants = [] } = req.body || {};
    if (!name) return res.status(400).json({ error: 'Name required' });
    const uniqParticipants = Array.from(new Set([req.user.username, ...participants]));
    if (memoryMode) {
      const chat = {
        _id: Date.now().toString(),
        name,
        type: 'group',
        participants: uniqParticipants,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastMessageAt: new Date(),
      };
      memChats.push(chat);
      return res.json(chat);
    }
    const chat = await Chat.create({
      name,
      type: 'group',
      participants: uniqParticipants,
      lastMessageAt: new Date(),
    });
    res.json(chat.toObject());
  } catch (err) {
    console.error('create chat error', err);
    res.status(500).json({ error: 'Failed to create chat' });
  }
});

// Start or fetch a direct chat with another user
app.post('/api/direct', authMiddleware, async (req, res) => {
  try {
    const { username: other } = req.body || {};
    const current = req.user.username;
    if (!other || other === current) return res.status(400).json({ error: 'Invalid user' });

    if (memoryMode) {
      let chat = memChats.find(
        (c) =>
          c.type === 'direct' &&
          c.participants.includes(current) &&
          c.participants.includes(other) &&
          c.participants.length === 2
      );
      if (!chat) {
        chat = {
          _id: Date.now().toString(),
          name: `${current} & ${other}`,
          type: 'direct',
          participants: [current, other],
          lastMessageAt: new Date(),
        };
        memChats.push(chat);
      }
      return res.json(chat);
    }

    let chat = await Chat.findOne({
      type: 'direct',
      participants: { $all: [current, other], $size: 2 },
    });
    if (!chat) {
      chat = await Chat.create({
        name: `${current} & ${other}`,
        type: 'direct',
        participants: [current, other],
        lastMessageAt: new Date(),
      });
    }
    res.json(chat.toObject());
  } catch (err) {
    console.error('direct chat error', err);
    res.status(500).json({ error: 'Failed to create direct chat' });
  }
});

// Add/remove participant to an existing chat (group)
app.post('/api/chats/:id/participants', authMiddleware, async (req, res) => {
  try {
    const chatId = req.params.id;
    const { username: targetUser, remove } = req.body || {};
    if (!targetUser) return res.status(400).json({ error: 'Username required' });

    if (memoryMode) {
      const chat = memChats.find((c) => c._id === chatId);
      if (!chat || chat.type !== 'group') return res.status(400).json({ error: 'Invalid chat' });
      if (remove) {
        chat.participants = chat.participants.filter((u) => u !== targetUser);
      } else if (!chat.participants.includes(targetUser)) {
        chat.participants.push(targetUser);
      }
      return res.json(chat);
    }

    const chat = await Chat.findById(chatId);
    if (!chat || chat.type !== 'group') return res.status(400).json({ error: 'Invalid chat' });
    if (remove) {
      chat.participants = chat.participants.filter((u) => u !== targetUser);
      await chat.save();
    } else if (!chat.participants.includes(targetUser)) {
      chat.participants.push(targetUser);
      await chat.save();
    }
    res.json(chat.toObject());
  } catch (err) {
    console.error('add participant error', err);
    res.status(500).json({ error: 'Failed to add participant' });
  }
});

// Bootstrap data for authenticated user
app.get('/api/bootstrap', authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    await ensureDefaultChat(user.username);
    const chats = await chatsForUser(user.username);
    const activeChatId = chats.length ? chats[0]._id : null;
    let messages = [];
    if (activeChatId) {
      const data = await latestMessages(activeChatId, 100);
      messages = data.reverse();
    }
    const users = memoryMode
      ? []
      : await User.find().select('username lastSeen updatedAt bio avatarUrl').lean();
    const self = users.find((u) => u.username === user.username) || { username: user.username };
    res.json({ user: self, chats, messages, activeChatId, users });
  } catch (err) {
    console.error('Error fetching bootstrap data:', err);
    res.status(500).json({ error: 'Failed to load data' });
  }
});

// List users (basic search via ?q=)
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    if (memoryMode) return res.json([]);
    const q = (req.query.q || '').toString().trim();
    const filter = q ? { username: new RegExp(q, 'i') } : {};
    const users = await User.find(filter)
      .select('username lastSeen updatedAt bio avatarUrl')
      .limit(50)
      .lean();
    res.json(users);
  } catch (err) {
    console.error('list users error', err);
    res.status(500).json({ error: 'Failed to list users' });
  }
});

// Self profile
app.get('/api/me', authMiddleware, async (req, res) => {
  if (memoryMode) return res.json({ username: req.user.username, bio: '', avatarUrl: '' });
  const user = await User.findOne({ username: req.user.username })
    .select('username lastSeen bio avatarUrl')
    .lean();
  res.json(user);
});

app.patch('/api/me', authMiddleware, async (req, res) => {
  if (memoryMode) return res.json({ username: req.user.username, bio: '', avatarUrl: '' });
  const { bio, avatarUrl } = req.body || {};
  const updated = await User.findOneAndUpdate(
    { username: req.user.username },
    { $set: { bio: bio || '', avatarUrl: avatarUrl || '' } },
    { new: true }
  )
    .select('username lastSeen bio avatarUrl')
    .lean();
  res.json(updated);
});

app.get('/api/users/:username', authMiddleware, async (req, res) => {
  if (memoryMode)
    return res.json({ username: req.params.username, bio: '', avatarUrl: '', lastSeen: null });
  const user = await User.findOne({ username: req.params.username })
    .select('username lastSeen bio avatarUrl')
    .lean();
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(user);
});

// Messages for a chat
app.get('/api/chats/:id/messages', authMiddleware, async (req, res) => {
  try {
    const chatId = req.params.id;
    const msgs = await latestMessages(chatId, 100);
    res.json(msgs.reverse());
  } catch (err) {
    console.error('fetch messages error', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Participants profiles for a chat
app.get('/api/chats/:id/users', authMiddleware, async (req, res) => {
  try {
    const chatId = req.params.id;
    if (memoryMode) return res.json([]);
    const chat = await Chat.findById(chatId);
    if (!chat) return res.status(404).json({ error: 'Chat not found' });
    const users = await User.find({ username: { $in: chat.participants } })
      .select('username bio avatarUrl lastSeen updatedAt')
      .lean();
    res.json(users);
  } catch (err) {
    console.error('fetch chat users error', err);
    res.status(500).json({ error: 'Failed to fetch chat users' });
  }
});

// Upload endpoint (for images)
app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const url = `/uploads/${req.file.filename}`;
  res.json({ url });
});

// Upload documentation endpoint (HLD, LLD, Requirements)
app.post('/api/upload-documentation', authMiddleware, documentUpload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const { documentType, description } = req.body || {};
    if (!documentType || !['HLD', 'LLD', 'Requirements'].includes(documentType)) {
      return res.status(400).json({ error: 'Invalid document type. Must be HLD, LLD, or Requirements' });
    }

    const docData = {
      filename: req.file.filename,
      originalName: req.file.originalname,
      fileUrl: `/uploads/${req.file.filename}`,
      fileSize: req.file.size,
      mimeType: req.file.mimetype,
      documentType,
      uploadedBy: req.user.username,
      description: description || '',
    };

    if (memoryMode) {
      memDocumentation.push({ ...docData, _id: Date.now().toString(), createdAt: new Date() });
      return res.json(docData);
    }

    const doc = await Documentation.create(docData);
    res.json(doc.toObject());
  } catch (err) {
    console.error('Documentation upload error:', err);
    res.status(500).json({ error: err.message || 'Failed to upload documentation' });
  }
});

// Get all documentation
app.get('/api/documentation', authMiddleware, async (req, res) => {
  try {
    const { documentType } = req.query || {};
    let filter = {};
    if (documentType && ['HLD', 'LLD', 'Requirements'].includes(documentType)) {
      filter.documentType = documentType;
    }

    if (memoryMode) {
      let docs = memDocumentation;
      if (filter.documentType) {
        docs = docs.filter((d) => d.documentType === filter.documentType);
      }
      return res.json(docs);
    }

    const docs = await Documentation.find(filter).sort({ createdAt: -1 }).lean();
    res.json(docs);
  } catch (err) {
    console.error('Get documentation error:', err);
    res.status(500).json({ error: 'Failed to fetch documentation' });
  }
});

// Get single documentation by ID
app.get('/api/documentation/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    if (memoryMode) {
      const doc = memDocumentation.find((d) => String(d._id) === String(id));
      if (!doc) return res.status(404).json({ error: 'Documentation not found' });
      return res.json(doc);
    }
    const doc = await Documentation.findById(id).lean();
    if (!doc) return res.status(404).json({ error: 'Documentation not found' });
    res.json(doc);
  } catch (err) {
    console.error('Get documentation error:', err);
    res.status(500).json({ error: 'Failed to fetch documentation' });
  }
});

// Delete documentation
app.delete('/api/documentation/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    if (memoryMode) {
      const doc = memDocumentation.find((d) => String(d._id) === String(id));
      if (!doc) return res.status(404).json({ error: 'Documentation not found' });
      if (doc.uploadedBy !== req.user.username) {
        return res.status(403).json({ error: 'Not authorized to delete this document' });
      }
      // Delete file from filesystem
      const filePath = path.join(uploadsDir, doc.filename);
      fs.unlink(filePath, () => {});
      memDocumentation = memDocumentation.filter((d) => String(d._id) !== String(id));
      return res.json({ success: true });
    }
    const doc = await Documentation.findById(id);
    if (!doc) return res.status(404).json({ error: 'Documentation not found' });
    if (doc.uploadedBy !== req.user.username) {
      return res.status(403).json({ error: 'Not authorized to delete this document' });
    }
    // Delete file from filesystem
    const filePath = path.join(uploadsDir, doc.filename);
    fs.unlink(filePath, () => {});
    await Documentation.findByIdAndDelete(id);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete documentation error:', err);
    res.status(500).json({ error: 'Failed to delete documentation' });
  }
});

io.on('connection', (socket) => {
  console.log('New client connected', socket.id);

  socket.on('auth:login', async (payload = {}) => {
    const { token } = payload;
    if (!token) return;
    try {
      const user = jwt.verify(token, JWT_SECRET);
      socket.user = user;
      onlineUsers.set(user.username, (onlineUsers.get(user.username) || 0) + 1);
      const set = userSockets.get(user.username) || new Set();
      set.add(socket.id);
      userSockets.set(user.username, set);
    if (!memoryMode && mongoose.connection.readyState === 1) {
        User.updateOne({ username: user.username }, { $set: { lastSeen: null } }).catch(() => {});
    }

      const userChats = await chatsForUser(user.username);
      userChats.forEach((c) => socket.join(c._id.toString()));
      io.emit('presence:update', { online: Array.from(onlineUsers.keys()) });
    } catch (err) {
      console.error('auth error', err.message);
    }
  });

  socket.on('chat:join', async (payload = {}) => {
    if (!socket.user) return;
    const { chatId } = payload;
    if (!chatId) return;
    try {
      let chat = null;
      if (memoryMode) {
        chat = memChats.find((c) => c._id === chatId);
      } else {
        chat = await Chat.findById(chatId);
      }
      if (!chat) return;
      if (!chat.participants.includes(socket.user.username)) return;
      socket.join(chatId.toString());
    } catch (err) {
      console.error('chat:join error', err.message);
    }
  });

  socket.on('typing', (payload = {}) => {
    const { chatId, isTyping } = payload;
    if (!chatId || !socket.user) return;
    socket.to(chatId.toString()).emit('typing', {
      chatId,
      username: socket.user.username,
      isTyping: !!isTyping,
    });
  });

  socket.on('chat:message', async (payload) => {
    try {
      if (!socket.user) return;
      const { text, chatId, imageUrl } = payload || {};
      if (!chatId || (!text && !imageUrl)) return;

      let chat = null;
      if (memoryMode) {
        chat = memChats.find((c) => c._id === chatId);
      } else {
        chat = await Chat.findById(chatId);
      }
      if (!chat) return;
      if (!chat.participants.includes(socket.user.username)) return;

      // ensure all online participants are joined to the room
      chat.participants.forEach((p) => {
        const ids = userSockets.get(p);
        if (ids) {
          ids.forEach((id) => {
            const s = io.sockets.sockets.get(id);
            if (s) s.join(chat._id.toString());
          });
        }
      });

      let saved = null;
      if (!memoryMode && mongoose.connection.readyState === 1) {
        const msg = new Message({
          chatId: chat._id,
          sender: socket.user.username,
          text,
          imageUrl,
          status: 'delivered',
          readBy: [],
        });
        saved = await msg.save();
        chat.lastMessageAt = new Date();
        await chat.save().catch(() => {});
      }
      if (memoryMode || !saved) {
        const memMsg = {
          _id: Date.now().toString(),
          chatId: chat._id,
          sender: socket.user.username,
          text,
          imageUrl,
          status: 'delivered',
          readBy: [],
          createdAt: new Date().toISOString(),
        };
        memMessages.push(memMsg);
        io.to(chat._id.toString()).emit('chat:message', memMsg);
        return;
      }

      const messageToEmit = {
        _id: saved._id,
        chatId: saved.chatId,
        sender: saved.sender,
        text: saved.text,
        imageUrl: saved.imageUrl,
        status: saved.status,
        readBy: saved.readBy || [],
        createdAt: saved.createdAt,
      };

      io.to(chat._id.toString()).emit('chat:message', messageToEmit);
    } catch (err) {
      console.error('Error handling chat:message:', err);
    }
  });

  socket.on('chat:read', async (payload = {}) => {
    const { chatId } = payload;
    if (!chatId || !socket.user) return;
    try {
      if (!memoryMode && mongoose.connection.readyState === 1) {
        await Message.updateMany(
          { chatId, readBy: { $ne: socket.user.username } },
          { $addToSet: { readBy: socket.user.username }, $set: { status: 'read' } }
        ).catch(() => {});
        const updated = await Message.find({ chatId })
          .sort({ createdAt: 1 })
          .limit(50)
          .lean();
        io.to(chatId.toString()).emit('chat:read', {
          chatId,
          readBy: socket.user.username,
          messages: updated,
        });
      } else {
        memMessages = memMessages.map((m) =>
          m.chatId === chatId
            ? { ...m, status: 'read', readBy: Array.from(new Set([...(m.readBy || []), socket.user.username])) }
            : m
        );
        const latest = memMessages.filter((m) => m.chatId === chatId).slice(-50);
        io.to(chatId.toString()).emit('chat:read', {
          chatId,
          readBy: socket.user.username,
          messages: latest,
        });
      }
    } catch (err) {
      console.error('Error handling chat:read:', err.message);
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected', socket.id);
    if (socket.user) {
      const current = onlineUsers.get(socket.user.username) || 0;
      if (current <= 1) onlineUsers.delete(socket.user.username);
      else onlineUsers.set(socket.user.username, current - 1);
      const set = userSockets.get(socket.user.username);
      if (set) {
        set.delete(socket.id);
        if (!set.size) userSockets.delete(socket.user.username);
        else userSockets.set(socket.user.username, set);
      }
      io.emit('presence:update', { online: Array.from(onlineUsers.keys()) });
      if (!memoryMode && mongoose.connection.readyState === 1) {
        User.updateOne({ username: socket.user.username }, { $set: { lastSeen: new Date() } }).catch(
          () => {}
        );
      }
    }
  });
});

const PORT = process.env.PORT || 3000;

connectMongo().then(() => {
  server.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
});

