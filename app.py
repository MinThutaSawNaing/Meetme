from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
import sqlite3
import uuid
import os
import json
import logging
from passlib.context import CryptContext
import jwt
from jwt.exceptions import InvalidTokenError
import threading
from fastapi.security import OAuth2PasswordBearer
from fastapi import Form

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="Meetme Chat API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your-secret-key-here"  # Change this in production
ALGORITHM = "HS256"

# Database setup
DATABASE_URL = "meetme.db"

# Thread-local storage for database connections
thread_local = threading.local()

def get_db():
    # Create a connection per thread
    if not hasattr(thread_local, "db_connection"):
        thread_local.db_connection = sqlite3.connect(DATABASE_URL)
        thread_local.db_connection.row_factory = sqlite3.Row
    
    return thread_local.db_connection

# Create tables
def init_db():
    conn = sqlite3.connect(DATABASE_URL)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Rooms table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id TEXT PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            name TEXT,
            created_by TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')
    
    # Messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            room_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            content_type TEXT NOT NULL,  -- text, image, video, gif
            content TEXT NOT NULL,
            file_path TEXT,
            file_size INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (room_id) REFERENCES rooms (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Room participants table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS room_participants (
            id TEXT PRIMARY KEY,
            room_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (room_id) REFERENCES rooms (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Pydantic models
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: EmailStr
    username: str
    created_at: datetime

class RoomCreate(BaseModel):
    name: Optional[str] = None

class RoomResponse(BaseModel):
    id: str
    code: str
    name: Optional[str]
    created_by: str
    created_at: datetime
    last_activity: datetime

class MessageCreate(BaseModel):
    content: str
    content_type: str = "text"  # text, image, video, gif

class MessageResponse(BaseModel):
    id: str
    room_id: str
    user_id: str
    username: str
    content_type: str
    content: str
    file_path: Optional[str]
    file_size: Optional[int]
    created_at: datetime

# Utility functions
def generate_room_code():
    import random
    return str(random.randint(100000, 999999))

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except InvalidTokenError:
        return None

# Dependency to get current user from token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = payload.get("sub")
    db = get_db()
    cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


# Auth endpoints
@app.post("/api/auth/signup", response_model=dict)
async def signup(user: UserCreate):
    db = get_db()
    
    # Check if user already exists
    cursor = db.execute("SELECT id FROM users WHERE email = ?", (user.email,))
    if cursor.fetchone():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user
    user_id = str(uuid.uuid4())
    password_hash = get_password_hash(user.password)
    
    db.execute(
        "INSERT INTO users (id, email, username, password_hash) VALUES (?, ?, ?, ?)",
        (user_id, user.email, user.username, password_hash)
    )
    db.commit()
    
    # Create access token
    access_token = create_access_token({"sub": user_id})
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/login", response_model=dict)
async def login(credentials: UserLogin):
    db = get_db()
    cursor = db.execute("SELECT * FROM users WHERE email = ?", (credentials.email,))
    user = cursor.fetchone()
    
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token = create_access_token({"sub": user["id"]})
    
    return {"access_token": access_token, "token_type": "bearer"}

# User endpoints
@app.get("/api/users/me", response_model=UserResponse)
async def get_current_user_info(user: dict = Depends(get_current_user)):
    return {
        "id": user["id"],
        "email": user["email"],
        "username": user["username"],
        "created_at": user["created_at"]
    }

# Room endpoints
@app.post("/api/rooms", response_model=RoomResponse)
async def create_room(
    room_data: RoomCreate, 
    user: dict = Depends(get_current_user)
):
    db = get_db()
    room_id = str(uuid.uuid4())
    room_code = generate_room_code()
    
    # Ensure code is unique
    while True:
        cursor = db.execute("SELECT id FROM rooms WHERE code = ?", (room_code,))
        if not cursor.fetchone():
            break
        room_code = generate_room_code()
    
    db.execute(
        "INSERT INTO rooms (id, code, name, created_by) VALUES (?, ?, ?, ?)",
        (room_id, room_code, room_data.name, user["id"])
    )
    
    # Add creator as participant
    participant_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO room_participants (id, room_id, user_id) VALUES (?, ?, ?)",
        (participant_id, room_id, user["id"])
    )
    
    db.commit()
    
    # Get the created room
    cursor = db.execute("SELECT * FROM rooms WHERE id = ?", (room_id,))
    room = cursor.fetchone()
    
    return {
        "id": room["id"],
        "code": room["code"],
        "name": room["name"],
        "created_by": room["created_by"],
        "created_at": room["created_at"],
        "last_activity": room["last_activity"]
    }

@app.post("/api/rooms/join/{room_code}", response_model=RoomResponse)
async def join_room(
    room_code: str,
    user: dict = Depends(get_current_user)
):
    db = get_db()
    
    # Find room by code
    cursor = db.execute("SELECT * FROM rooms WHERE code = ?", (room_code,))
    room = cursor.fetchone()
    
    if not room:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Room not found"
        )
    
    # Check if user is already a participant
    cursor = db.execute(
        "SELECT id FROM room_participants WHERE room_id = ? AND user_id = ?",
        (room["id"], user["id"])
    )
    if cursor.fetchone():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Already joined this room"
        )
    
    # Add user as participant
    participant_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO room_participants (id, room_id, user_id) VALUES (?, ?, ?)",
        (participant_id, room["id"], user["id"])
    )
    
    # Update room's last activity
    db.execute(
        "UPDATE rooms SET last_activity = CURRENT_TIMESTAMP WHERE id = ?",
        (room["id"],)
    )
    
    db.commit()
    
    return {
        "id": room["id"],
        "code": room["code"],
        "name": room["name"],
        "created_by": room["created_by"],
        "created_at": room["created_at"],
        "last_activity": room["last_activity"]
    }

@app.get("/api/rooms/{room_id}/messages", response_model=List[MessageResponse])
async def get_room_messages(
    room_id: str,
    user: dict = Depends(get_current_user)
):
    db = get_db()
    
    # Check if user is a participant of the room
    cursor = db.execute(
        "SELECT id FROM room_participants WHERE room_id = ? AND user_id = ?",
        (room_id, user["id"])
    )
    if not cursor.fetchone():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a participant of this room"
        )
    
    # Get messages with username
    cursor = db.execute('''
        SELECT m.*, u.username 
        FROM messages m 
        JOIN users u ON m.user_id = u.id 
        WHERE m.room_id = ? 
        ORDER BY m.created_at
    ''', (room_id,))
    
    messages = []
    for row in cursor.fetchall():
        messages.append({
            "id": row["id"],
            "room_id": row["room_id"],
            "user_id": row["user_id"],
            "username": row["username"],
            "content_type": row["content_type"],
            "content": row["content"],
            "file_path": row["file_path"],
            "file_size": row["file_size"],
            "created_at": row["created_at"]
        })
    
    return messages

# Separate endpoints for text messages and file uploads
@app.post("/api/rooms/{room_id}/messages", response_model=MessageResponse)
async def create_text_message(
    room_id: str,
    message_data: MessageCreate,
    user: dict = Depends(get_current_user)
):
    db = get_db()
    cursor = db.execute(
        "SELECT id FROM room_participants WHERE room_id = ? AND user_id = ?",
        (room_id, user["id"])
    )
    if not cursor.fetchone():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a participant of this room"
        )
    
    message_id = str(uuid.uuid4())
    
    # Insert message into database
    db.execute(
        '''INSERT INTO messages 
           (id, room_id, user_id, content_type, content) 
           VALUES (?, ?, ?, ?, ?)''',
        (message_id, room_id, user["id"], message_data.content_type, message_data.content)
    )
    
    # Update room's last activity
    db.execute(
        "UPDATE rooms SET last_activity = CURRENT_TIMESTAMP WHERE id = ?",
        (room_id,)
    )
    
    db.commit()
    
    # Get the created message with username
    cursor = db.execute('''
        SELECT m.*, u.username 
        FROM messages m 
        JOIN users u ON m.user_id = u.id 
        WHERE m.id = ?
    ''', (message_id,))
    
    message = cursor.fetchone()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create message"
        )
    
    # Broadcast to WebSocket connections
    await manager.broadcast_to_room({
        "type": "new_message",
        "room_id": room_id
    }, room_id)
    
    return {
        "id": message["id"],
        "room_id": message["room_id"],
        "user_id": message["user_id"],
        "username": message["username"],
        "content_type": message["content_type"],
        "content": message["content"],
        "file_path": message["file_path"],
        "file_size": message["file_size"],
        "created_at": message["created_at"]
    }

@app.post("/api/rooms/{room_id}/files", response_model=MessageResponse)
async def upload_file_message(
    room_id: str,
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user)
):
    db = get_db()
    cursor = db.execute(
        "SELECT id FROM room_participants WHERE room_id = ? AND user_id = ?",
        (room_id, user["id"])
    )
    if not cursor.fetchone():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a participant of this room"
        )
    
    message_id = str(uuid.uuid4())
    file_path = None
    file_size = None
    content = ""
    content_type = "file"

    if file and file.filename:
        # Handle file upload
        os.makedirs("uploads", exist_ok=True)
        filename = file.filename
        file_extension = os.path.splitext(filename)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        file_path = f"uploads/{unique_filename}"
        file_size = 0
        
        with open(file_path, "wb") as buffer:
            while True:
                chunk = await file.read(1024)
                if not chunk:
                    break
                file_size += len(chunk)
                buffer.write(chunk)
        
        # Determine content type based on file extension
        if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
            content_type = "gif" if filename.lower().endswith('.gif') else "image"
        elif filename.lower().endswith(('.mp4', '.avi', '.mov', '.wmv')):
            content_type = "video"
        else:
            content_type = "file"
        
        # Store the original filename as content
        content = filename
    
    # Insert message into database
    db.execute(
        '''INSERT INTO messages 
           (id, room_id, user_id, content_type, content, file_path, file_size) 
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (message_id, room_id, user["id"], content_type, content, file_path, file_size)
    )
    
    # Update room's last activity
    db.execute(
        "UPDATE rooms SET last_activity = CURRENT_TIMESTAMP WHERE id = ?",
        (room_id,)
    )
    
    db.commit()
    
    # Get the created message with username
    cursor = db.execute('''
        SELECT m.*, u.username 
        FROM messages m 
        JOIN users u ON m.user_id = u.id 
        WHERE m.id = ?
    ''', (message_id,))
    
    message = cursor.fetchone()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create message"
        )
    
    # Broadcast to WebSocket connections
    await manager.broadcast_to_room({
        "type": "new_message",
        "room_id": room_id
    }, room_id)
    
    return {
        "id": message["id"],
        "room_id": message["room_id"],
        "user_id": message["user_id"],
        "username": message["username"],
        "content_type": message["content_type"],
        "content": message["content"],
        "file_path": message["file_path"],
        "file_size": message["file_size"],
        "created_at": message["created_at"]
    }

# WebSocket manager
# WebSocket manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict = {}

    async def connect(self, websocket: WebSocket, room_id: str, user_id: str):
        await websocket.accept()
        if room_id not in self.active_connections:
            self.active_connections[room_id] = {}
        self.active_connections[room_id][user_id] = websocket

    def disconnect(self, room_id: str, user_id: str):
        if room_id in self.active_connections and user_id in self.active_connections[room_id]:
            del self.active_connections[room_id][user_id]
            if not self.active_connections[room_id]:
                del self.active_connections[room_id]

    async def broadcast_to_room(self, message: dict, room_id: str, exclude_user_id: Optional[str] = None):
        if room_id in self.active_connections:
            for uid, connection in self.active_connections[room_id].items():
                if uid != exclude_user_id:
                    try:
                        await connection.send_json(message)  # Changed to send_json
                    except Exception as e:
                        logger.error(f"Error sending to {uid}: {e}")

manager = ConnectionManager()

@app.websocket("/ws/rooms/{room_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str, token: str):
    payload = decode_access_token(token)
    if payload is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    user_id = payload.get("sub")
    db = get_db()
    cursor = db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    cursor = db.execute("SELECT id FROM room_participants WHERE room_id = ? AND user_id = ?", (room_id, user_id))
    if not cursor.fetchone():
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    await manager.connect(websocket, room_id, user_id)
    try:
        while True:
            # Wait for any message from client (we don't need to process it)
            await websocket.receive_text()
            # When we receive a message, broadcast to all clients in the room
            await manager.broadcast_to_room({  # Send JSON object instead of string
                "type": "new_message",
                "room_id": room_id
            }, room_id)
    except WebSocketDisconnect:
        manager.disconnect(room_id, user_id)

async def fetch_latest_messages_for_room(room_id: str):
    try:
        await manager.broadcast_to_room({
            "type": "new_message",
            "room_id": room_id
        }, room_id)
    except Exception as e:
        logger.error(f"Error fetching latest messages for room {room_id}: {e}")

# Serve the index.html file
@app.get("/", response_class=HTMLResponse)
async def read_root():
    index_path = os.path.join("static", "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="index.html not found in /static")
    with open(index_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

# Cleanup scheduler
@app.on_event("startup")
async def startup_event():
    import asyncio
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    
    scheduler = AsyncIOScheduler()

    async def cleanup_inactive_rooms():
        db = get_db()
        six_days_ago = (datetime.now() - timedelta(days=6)).strftime("%Y-%m-%d %H:%M:%S")
        cursor = db.execute("SELECT id FROM rooms WHERE last_activity < ?", (six_days_ago,))
        for room in cursor.fetchall():
            rid = room["id"]
            db.execute("DELETE FROM messages WHERE room_id = ?", (rid,))
            db.execute("DELETE FROM room_participants WHERE room_id = ?", (rid,))
            db.execute("DELETE FROM rooms WHERE id = ?", (rid,))
            logger.info(f"Deleted inactive room {rid}")
        db.commit()

    scheduler.add_job(cleanup_inactive_rooms, 'interval', days=1)
    scheduler.start()

# Ensure static dir exists before mounting
STATIC_DIR = "static"
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR, html=True), name="static")

# Ensure uploads directory exists
os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
