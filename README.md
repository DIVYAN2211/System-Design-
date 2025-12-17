## Real-Time Chat Demo

Minimal real-time chat app with:

- Node.js + Express backend
- WebSocket (Socket.IO) for persistent connections
- Optional MongoDB Atlas storage for messages
- Simple modern web UI to demo real-time chat

### 1. Prerequisites

- Node.js 18+ installed
- MongoDB (choose one):
  - Local MongoDB (e.g., via MongoDB Community Server) — works with MongoDB Compass.
  - MongoDB Atlas cluster (cloud).

### 2. Install dependencies

From the project root:

```bash
npm install
```

### 3. Configure environment

Pick one of the following:

**Local MongoDB (Compass-friendly)**
1) Copy `env.local.example` to `.env`.
2) Ensure `mongod` is running locally (default port 27017).
3) `.env` example:
   ```bash
   MONGODB_URI=mongodb://127.0.0.1:27017/chatapp
   PORT=3000
   ```

**MongoDB Atlas**
Create a `.env` file in the project root:
```bash
MONGODB_URI=mongodb+srv://<username>:<password>@<cluster>/<database>?retryWrites=true&w=majority
PORT=3000
```

If you skip `MONGODB_URI`, the app still runs, but messages will not persist.

### 4. Run locally

```bash
npm start
```

Then open `http://localhost:3000` in one or more browser windows to test real-time chat.

### 5. View/edit data in MongoDB Compass (local setup)

1) Open MongoDB Compass.
2) Connect using `mongodb://127.0.0.1:27017`.
3) Select the `chatapp` database and the `messages` collection to view stored chats.

### 6. Deploy (example: Render / Railway / similar)

1. Create a new web service from this repo.
2. Set the build command (if needed) to:

   ```bash
   npm install
   ```

3. Set start command:

   ```bash
   npm start
   ```

4. Add environment variables in the dashboard:

   - `MONGODB_URI` – your Atlas connection string
   - `PORT` – usually provided automatically by the platform; if so, remove it from `.env`

Once deployed, open the service URL in two browsers to demo real-time chat over WebSockets with persisted messages.


