import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Session # Import Session for specific DB operations
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy import or_, func, select, case
from sqlalchemy.orm import aliased
from werkzeug.utils import secure_filename
from botocore.exceptions import NoCredentialsError
import boto3
from dotenv import load_dotenv
from datetime import datetime, timezone as dt_timezone
from collections import defaultdict
import secrets
import requests # To call the main app's API

load_dotenv()

# --- Flask App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('CHAT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Add R2 config if needed for uploads
app.config['R2_BUCKET_NAME'] = os.environ.get('R2_BUCKET_NAME')

# --- Database Setup ---
db = SQLAlchemy()

# --- IMPORTANT: Define Models IDENTICAL to Main App ---
# Copy the exact definitions for User and Follow from your main app's models.py
# Ensure __tablename__ matches if specified in the original models.
class User(db.Model):
    __tablename__ = 'user' # Make sure this matches main app if it's set there
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    profile_image = db.Column(db.String(255), default='/static/images/default.png')
    display_name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    bio = db.Column(db.Text, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    level = db.Column(db.Integer, default=1)
    color_scheme = db.Column(db.String(50), default='primary')
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)

class Follow(db.Model):
    __tablename__ = 'follow' # Make sure this matches main app if it's set there
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    # ... other columns if any ...

# --- Chat-Specific Model ---
class Message(db.Model):
    __tablename__ = 'message' # Explicitly define table name
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    seen = db.Column(db.Boolean, default=False)
    media_url = db.Column(db.Text)
    deleted_for_everyone = db.Column(db.Boolean, default=False, nullable=False)

# --- Initialize Extensions ---
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*") # Allow CORS for SocketIO if needed
login_manager = LoginManager()
login_manager.init_app(app)
# Where to redirect if @login_required fails? We handle login via JS, so maybe nowhere.
login_manager.login_view = None # No automatic redirect page

# S3 client setup (if needed for upload)
s3 = None
if all(os.environ.get(k) for k in ['R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'R2_ENDPOINT_URL']):
    s3session = boto3.session.Session()
    s3 = s3session.client(
        service_name='s3',
        aws_access_key_id=os.environ.get('R2_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('R2_SECRET_ACCESS_KEY'),
        endpoint_url=os.environ.get('R2_ENDPOINT_URL')
    )
else:
    print("Warning: R2 credentials not fully configured. File uploads may fail.")


# --- Flask-Login Setup ---
@login_manager.user_loader
def load_user(user_id):
    """Loads user for the session management WITHIN the chat app."""
    try:
        # Use the chat app's db session
        return db.session.get(User, int(user_id))
    except Exception as e:
        print(f"Error loading user {user_id}: {e}")
        return None

# --- NEW Endpoint to Establish Chat Session ---
# This endpoint is called by chat.html's JavaScript AFTER successful verification
# from the main app's API.
@app.route('/login_chat_session', methods=['POST'])
def login_chat_session():
    data = request.get_json()
    user_id_from_main_app = data.get('user_id')

    if not user_id_from_main_app:
        return jsonify({"status": "error", "message": "Missing user ID"}), 400

    # Fetch the user from the DB using the chat app's session/models
    user = db.session.get(User, int(user_id_from_main_app))
    if user:
        # Log the user in within the chat app's session context
        login_user(user) # Duration, remember=True optional
        print(f"[Chat Login] Session established for user {user.id}")
        return jsonify({"status": "success"}), 200
    else:
        print(f"[Chat Login] Could not find user {user_id_from_main_app} in DB.")
        # This indicates a potential sync issue or bad data from main API
        return jsonify({"status": "error", "message": "User not found locally"}), 404

@app.route('/logout_chat')
@login_required # Use chat app's @login_required
def logout_chat():
    """Logs the user out of the chat app's session."""
    logout_user() # Use chat app's logout_user
    print("[Chat Logout] User session cleared.")
    return jsonify({"status": "success"}), 200


# --- Helper functions (from chat.py) ---
def get_room_name(user_id1, user_id2):
    return f"{min(user_id1, user_id2)}_{max(user_id1, user_id2)}"

# Keep user_connections and is_user_online if needed for status
user_connections = defaultdict(set)
def is_user_online(user_id):
    return user_id in user_connections and len(user_connections[user_id]) > 0

def get_current_user_status(user_id):
    target_user = db.session.get(User, user_id)
    if not target_user:
        return {'online': False, 'last_seen': None}
    is_online = is_user_online(user_id)
    last_seen_iso_utc = None
    if not is_online and target_user.last_seen:
        last_seen_utc = target_user.last_seen
        if last_seen_utc.tzinfo is None:
             last_seen_utc = last_seen_utc.replace(tzinfo=dt_timezone.utc)
        else:
             last_seen_utc = last_seen_utc.astimezone(dt_timezone.utc)
        last_seen_iso_utc = last_seen_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    return {'online': is_online, 'last_seen': last_seen_iso_utc}

# --- Chat Routes (Moved & Adapted) ---

@app.route('/')
def index():
    """
    Serves chat.html. It will initially show the login form
    if the user isn't authenticated in *this* app's session.
    """
    # Pass user object if logged in, else None
    return render_template('chat.html', current_user_chat=current_user if current_user.is_authenticated else None, on_phone=False) # Simplify on_phone or detect differently


# Secure all data routes with the chat app's login_required
@app.route('/chat_users')
@login_required
def get_users():
    """Route to get the list of users for the chat sidebar (basic info + status)."""
    # Ensure this uses current_user from the chat app's session
    try:
        # Query users *except* the currently logged-in chat user
        users = User.query.filter(User.id != current_user.id).order_by(User.display_name).all()
        user_list = []

        # Fetch follow relationships involving the current user
        # Using the Follow model defined within this chat_server.py
        followed_users = Follow.query.filter(
            or_(Follow.follower_id == current_user.id, Follow.followed_id == current_user.id)
        ).all()
        # Create sets for faster lookup
        followed_ids = {f.followed_id for f in followed_users if f.follower_id == current_user.id}
        follower_ids = {f.follower_id for f in followed_users if f.followed_id == current_user.id}
        connected_user_ids = followed_ids.union(follower_ids)

        for user in users:
            # Only include users the current user is connected with (follows or is followed by)
            if user.id in connected_user_ids:
                user_status = get_current_user_status(user.id)
                user_list.append({
                    'id': user.id,
                    'username': user.username,
                    'profile_image': user.profile_image,
                    'bio': user.bio,
                    'joined': user.created_at.isoformat() + 'Z' if user.created_at else None,
                    'level': user.level,
                    'display_name': user.display_name,
                    'online': user_status['online'],
                    'last_seen': user_status['last_seen'],
                })
        return jsonify(user_list)
    except Exception as e:
        print(f"Error in /chat_users route: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to load users"}), 500


@app.route('/api/chat_previews')
@login_required
def get_chat_previews():
    # ... (Keep the existing logic from chat.py) ...
    # Make sure it uses current_user.id from the chat app's session
    current_user_id = current_user.id
    try:
        # Subquery... (identical logic should work)
        partner_subquery = select(
            case(
                (Message.sender_id == current_user_id, Message.receiver_id),
                else_=Message.sender_id
            ).label('partner_id'),
            func.max(Message.id).label('max_message_id')
        ).where(
            or_(Message.sender_id == current_user_id, Message.receiver_id == current_user_id),
            Message.deleted_for_everyone == False # Exclude deleted messages from previews
        ).group_by('partner_id').subquery()

        m_alias = aliased(Message)

        latest_messages_query = select(
            m_alias.id, m_alias.sender_id, m_alias.receiver_id, m_alias.content,
            m_alias.media_url, m_alias.timestamp, m_alias.seen,
            partner_subquery.c.partner_id
        ).join(
            partner_subquery, m_alias.id == partner_subquery.c.max_message_id
        )

        latest_messages_results = db.session.execute(latest_messages_query).fetchall()

        # Unread counts... (identical logic)
        unread_counts_query = select(
            Message.sender_id.label('partner_id'),
            func.count(Message.id).label('unread_count')
        ).where(
            Message.receiver_id == current_user_id,
            Message.seen == False,
            Message.deleted_for_everyone == False # Exclude deleted from unread count
        ).group_by(Message.sender_id)

        unread_counts_results = db.session.execute(unread_counts_query).fetchall()

        # Organize data... (identical logic)
        previews = {}
        for row in latest_messages_results:
             (msg_id, sender_id, receiver_id, content, media_url, timestamp, seen, partner_id) = row
             previews[partner_id] = {
                 'latest_message': {
                     'id': msg_id, 'sender_id': sender_id, 'receiver_id': receiver_id,
                     'content': content, 'media_url': media_url,
                     'timestamp': timestamp.isoformat() + 'Z', 'seen': seen,
                     'deleted_for_everyone': False # Explicitly false as we filtered
                 },
                 'unread_count': 0
             }

        for row in unread_counts_results:
             (partner_id, count) = row
             if partner_id in previews:
                 previews[partner_id]['unread_count'] = count
             else:
                  # If only unread messages exist FROM a partner
                  previews[partner_id] = {'latest_message': None, 'unread_count': count}

        return jsonify(previews)

    except Exception as e:
        print(f"Error in /api/chat_previews route: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to load chat previews"}), 500


@app.route('/messages/<int:receiver_id>')
@login_required
def get_messages(receiver_id):
    # ... (Keep existing logic from chat.py) ...
    # Ensure it uses current_user.id from chat app's session
    sender_id = current_user.id
    room_name = get_room_name(sender_id, receiver_id)

    # Fetch messages, including deleted ones (frontend handles display)
    messages = Message.query.filter(
        ((Message.sender_id == sender_id) & (Message.receiver_id == receiver_id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == sender_id))
    ).order_by(Message.timestamp).all()

    message_list = []
    messages_to_mark_seen = []
    for msg in messages:
        is_self = msg.sender_id == sender_id
        # Ensure timestamp is timezone-aware (UTC) before formatting
        if msg.timestamp.tzinfo is None:
            msg_timestamp_utc = msg.timestamp.replace(tzinfo=dt_timezone.utc)
        else:
            msg_timestamp_utc = msg.timestamp.astimezone(dt_timezone.utc)

        # Mark as seen if receiver is viewing (and message not deleted)
        if not is_self and not msg.seen and not msg.deleted_for_everyone:
             # Collect messages to update after loop for efficiency
             messages_to_mark_seen.append(msg)


        # Use placeholder content if deleted for everyone
        display_content = msg.content if not msg.deleted_for_everyone else "[This message was deleted]"
        display_media_url = msg.media_url if not msg.deleted_for_everyone else None

        message_list.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'receiver_id': msg.receiver_id,
            'content': display_content,
            'timestamp': msg_timestamp_utc.strftime('%H:%M'), # Format time
            'date': msg_timestamp_utc.isoformat(), # Send full ISO date
            'seen': msg.seen,
            'is_self': is_self,
            'media_url': display_media_url,
            'deleted_for_everyone': msg.deleted_for_everyone
        })

    # Batch update seen status after fetching
    if messages_to_mark_seen:
         try:
             message_ids_to_update = [m.id for m in messages_to_mark_seen]
             Message.query.filter(Message.id.in_(message_ids_to_update)).update({Message.seen: True}, synchronize_session=False)
             db.session.commit()
             print(f"[Get Messages] Marked {len(message_ids_to_update)} messages as seen for user {sender_id} from {receiver_id}")

             # Notify the sender that their messages were read
             sender_room = str(receiver_id) # Target the sender's user-specific room/socket
             chat_room = get_room_name(sender_id, receiver_id)
             socketio.emit('messages_marked_seen_by_recipient',
                          {'reader_id': sender_id}, # Tell sender WHO read
                          room=chat_room, # Emit to shared room (client filters)
                          # Or use room=sender_room if using user-specific rooms
                          include_self=False) # Don't notify self

         except Exception as e:
             db.session.rollback()
             print(f"Error marking messages seen: {e}")


    return jsonify(message_list)


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    # ... (Keep existing logic from chat.py) ...
    # Ensure s3 client is initialized
    if s3 is None:
        return jsonify({'error': 'Media upload service not configured.'}), 503

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    # receiver_id = request.form.get('receiver_id') # No longer needed directly

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        filename = secure_filename(f"chat_media_{secrets.token_hex(8)}{os.path.splitext(file.filename)[1]}")
        object_key = f"uploads/chat_media/{filename}"
        try:
            s3.upload_fileobj(
                file,
                app.config['R2_BUCKET_NAME'],
                object_key,
                ExtraArgs={'ContentType': file.content_type}
            )
            file_url = f"https://pub-cd0c5ba1d4df4dbcabe2fe821f5b24c2.r2.dev/{object_key}" # Replace if needed
            return jsonify({'url': file_url})

        except NoCredentialsError:
            print("R2 Credentials error during upload")
            return jsonify({'error': 'Media storage credentials error.'}), 500
        except Exception as e:
            print(f"R2 Upload error: {e}")
            return jsonify({'error': f'Media upload failed: {str(e)}'}), 500
    else:
        return jsonify({'error': 'Invalid file.'}), 400


@app.route('/api/user_status/<int:user_id>')
@login_required
def get_user_status_api(user_id):
    # ... (Keep existing logic from chat.py) ...
    target_user = db.session.get(User, user_id)
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    status_data = get_current_user_status(user_id) # Use helper
    status_data['user_id'] = user_id # Ensure user_id is included
    return jsonify(status_data)


@app.route('/api/message_status/<int:message_id>')
@login_required
def get_message_status(message_id):
    # ... (Keep existing logic from chat.py) ...
    try:
        message = db.session.get(Message, message_id)
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        if message.sender_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        return jsonify({'message_id': message.id, 'seen': message.seen}), 200
    except Exception as e:
        print(f"Error in /api/message_status/{message_id}: {e}")
        return jsonify({'error': 'An internal error occurred'}), 500

# --- SocketIO Handlers (Moved & Adapted) ---

# IMPORTANT: Ensure SocketIO handlers check authentication using the
# chat app's `current_user` derived from its session.

@socketio.on('connect')
def handle_connect():
    # Check auth based on chat app's session
    if not current_user.is_authenticated:
        print('[Chat WS Connect] Unauthenticated user connection rejected.')
        return False # Reject connection

    user_id = current_user.id
    sid = request.sid
    is_first_connection = not is_user_online(user_id)
    user_connections[user_id].add(sid)
    join_room(str(user_id)) # User-specific room for potential direct emits
    print(f'[Chat WS Connect] User {user_id} connected (SID: {sid}). Total connections: {len(user_connections[user_id])}.')

    # Broadcast online status update to others
    # Avoid doing DB update here, last_seen updated on disconnect
    socketio.emit('update_user_status', {
        'user_id': user_id,
        'online': True,
        'last_seen': None
    }, skip_sid=sid) # Don't send to self

@socketio.on('disconnect')
def handle_disconnect():
    disconnected_sid = request.sid
    user_id_to_remove = None
    for uid, sids in user_connections.items():
        if disconnected_sid in sids:
            user_id_to_remove = uid
            break

    if user_id_to_remove:
        user_id = user_id_to_remove
        user_connections[user_id].remove(disconnected_sid)
        # leave_room(str(user_id), sid=disconnected_sid) # Leave user-specific room

        if len(user_connections[user_id]) == 0:
            print(f'[Chat WS Disconnect] User {user_id} last connection closed (SID: {disconnected_sid}). Marking offline.')
            del user_connections[user_id]

            # Update last_seen in DB
            try:
                # Use a separate session for safety in background tasks? Or main session if simple.
                with Session(db.engine) as session: # Use separate session scope
                    user = session.get(User, user_id)
                    if user:
                        utc_now = datetime.now(dt_timezone.utc)
                        user.last_seen = utc_now
                        session.commit()
                        last_seen_iso_utc = utc_now.strftime('%Y-%m-%dT%H:%M:%SZ')
                        print(f'[DB Update] Updated last_seen for disconnected user {user_id}.')

                        # Broadcast offline status update AFTER DB commit
                        socketio.emit('update_user_status', {
                            'user_id': user_id,
                            'online': False,
                            'last_seen': last_seen_iso_utc
                        }) # Broadcast to all others
                    else:
                         print(f'[Chat WS Disconnect] User {user_id} not found in DB for last_seen update.')
            except Exception as e:
                print(f"[Chat WS Disconnect] Error updating last_seen for user {user_id}: {e}")
        else:
             print(f'[Chat WS Disconnect] User {user_id} disconnected (SID: {disconnected_sid}). Remaining connections: {len(user_connections[user_id])}.')
    else:
        print(f'[Chat WS Disconnect] SID {disconnected_sid} not found in user_connections map.')


@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated: return # Check chat app auth

    sender_id = current_user.id
    try:
        receiver_id = int(data['receiver_id'])
    except (KeyError, ValueError):
        print(f"[Send Message] Error: Invalid receiver_id from user {sender_id}.")
        return

    content = data.get('content', '').strip()
    media_url = data.get('media_url')
    local_id = data.get('localId') # Get local ID sent by client

    if not content and not media_url:
        print(f"[Send Message] Attempted empty message from {sender_id} to {receiver_id}")
        return # Don't save or emit empty messages

    try:
        msg = Message(sender_id=sender_id, receiver_id=receiver_id, content=content, media_url=media_url, seen=False)
        db.session.add(msg)
        db.session.commit() # Commit to get ID and timestamp

        room = get_room_name(sender_id, receiver_id)
        message_data_to_emit = {
            'id': msg.id,
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'content': content,
            'media_url': media_url,
            'timestamp': msg.timestamp.strftime('%H:%M'), # Use consistent formatting
            'date': msg.timestamp.replace(tzinfo=dt_timezone.utc).isoformat(), # Send ISO UTC
            'seen': False,
            'deleted_for_everyone': False,
            'localId': local_id # Include local ID in confirmation emit
        }

        # Emit to the room (sender + receiver)
        socketio.emit('receive_message', message_data_to_emit, room=room)
        print(f"[Send Message] Sent message {msg.id} from {sender_id} to {receiver_id} in room {room}.")

        # Calculate unread count for receiver
        unread_count = db.session.query(func.count(Message.id)).filter(
             Message.receiver_id == receiver_id,
             Message.sender_id == sender_id, # Messages FROM sender TO receiver
             Message.seen == False,
             Message.deleted_for_everyone == False
        ).scalar() or 0

        # Emit unread count update specifically to the receiver
        # Option 1: Use user-specific room
        # socketio.emit('update_unread_count', {'sender_id': sender_id, 'unread_count': unread_count}, room=str(receiver_id))
        # Option 2: Emit to shared room, client filters based on who sent update
        socketio.emit('update_unread_count', {'sender_id': sender_id, 'unread_count': unread_count}, room=room, include_self=False) # exclude sender


    except Exception as e:
        db.session.rollback()
        print(f"[Send Message] Error saving/emitting message: {e}")
        # Optionally emit an error back to the sender's SID
        # emit('send_error', {'localId': local_id, 'error': 'Failed to send message'}, room=request.sid)

# --- Add other SocketIO handlers ('join_chat', 'typing', 'stop_typing', 'delete_message', 'mark_chat_read', etc.) ---
# --- Ensure they all check `current_user.is_authenticated` first ---
# --- and use the chat app's `current_user` context. ---

@socketio.on('join_chat')
def handle_join_chat(data):
    if not current_user.is_authenticated: return
    sender_id = current_user.id
    try:
        receiver_id = int(data['receiver_id'])
        room = get_room_name(sender_id, receiver_id)
        join_room(room)
        print(f'[Chat WS Join] User {sender_id} joined room {room} with User {receiver_id}')

        # Mark messages as read upon joining the chat
        # Call the mark_chat_read logic directly or emit event to self if preferred
        handle_mark_chat_read({'sender_id': receiver_id}) # Pass the *other* user's ID

    except (KeyError, ValueError):
         print(f"[Join Chat] Error: Invalid receiver_id from user {sender_id}: {data}")
    except Exception as e:
         print(f"[Join Chat] Error for user {sender_id}: {e}")


@socketio.on('mark_chat_read')
def handle_mark_chat_read(data):
    if not current_user.is_authenticated: return
    reader_id = current_user.id
    try:
        sender_id_to_mark = int(data['sender_id']) # The ID of the person whose messages we are reading

        # Use bulk update for efficiency
        updated_count = db.session.query(Message).filter(
            Message.receiver_id == reader_id,
            Message.sender_id == sender_id_to_mark,
            Message.seen == False,
            Message.deleted_for_everyone == False
        ).update({Message.seen: True}, synchronize_session=False) # Update matching messages

        if updated_count > 0:
             db.session.commit()
             print(f"[Mark Read] User {reader_id} marked {updated_count} messages from {sender_id_to_mark} as read.")

             # Notify the *original sender* that their messages were seen by the reader
             sender_room = str(sender_id_to_mark)
             chat_room = get_room_name(reader_id, sender_id_to_mark)
             socketio.emit('messages_marked_seen_by_recipient',
                          {'reader_id': reader_id}, # Tell sender WHO read
                          room=chat_room,
                          include_self=False) # Don't tell self

             # Emit a zero count update back to the current user (reader)
             # to clear their own badge for this chat partner immediately.
             socketio.emit('update_unread_count', {
                  'sender_id': sender_id_to_mark, # The chat partner whose badge needs clearing
                  'unread_count': 0
             }, room=str(reader_id)) # Target the reader specifically

        # else:
        #      print(f"[Mark Read] No unread messages found from {sender_id_to_mark} for user {reader_id}.")


    except (KeyError, ValueError):
        print(f"[Mark Read] Error: Invalid sender_id from user {reader_id}: {data}")
    except Exception as e:
        db.session.rollback()
        print(f"[Mark Read] Error for user {reader_id}: {e}")


@socketio.on('typing')
def handle_typing(data):
    if not current_user.is_authenticated: return
    sender_id = current_user.id
    receiver_id = data.get('receiver_id')
    if not receiver_id: return
    try:
        room = get_room_name(sender_id, int(receiver_id))
        emit('user_typing', {'sender_id': sender_id}, room=room, include_self=False)
    except ValueError:
        print(f"[Typing] Invalid receiver_id from {sender_id}: {receiver_id}")


@socketio.on('stop_typing')
def handle_stop_typing(data):
    if not current_user.is_authenticated: return
    sender_id = current_user.id
    receiver_id = data.get('receiver_id')
    if not receiver_id: return
    try:
        room = get_room_name(sender_id, int(receiver_id))
        emit('user_stopped_typing', {'sender_id': sender_id}, room=room, include_self=False)
    except ValueError:
        print(f"[Stop Typing] Invalid receiver_id from {sender_id}: {receiver_id}")


@socketio.on('delete_message')
def handle_delete_message(data):
    if not current_user.is_authenticated: return

    message_id = data.get('message_id')
    if not message_id: return

    try:
        # Use separate session for safety? Or main is fine for simple operations.
        with Session(db.engine) as session:
            message = session.get(Message, message_id)

            if not message:
                print(f"[Delete Msg] Message {message_id} not found.")
                emit('delete_error', {'message_id': message_id, 'error': 'Message not found'}, room=request.sid)
                return

            if message.sender_id != current_user.id:
                print(f"[Delete Msg] Unauthorized attempt by user {current_user.id} on message {message_id}.")
                emit('delete_error', {'message_id': message_id, 'error': 'Unauthorized'}, room=request.sid)
                return

            if message.deleted_for_everyone: return # Already deleted

            # Perform deletion update
            message.content = "[This message was deleted]" # Consistent placeholder
            message.media_url = None
            message.deleted_for_everyone = True
            session.commit() # Commit within the session

            deleted_message_data = {
                'message_id': message.id,
                'new_content': message.content, # Send the placeholder text
                'date': message.timestamp.replace(tzinfo=dt_timezone.utc).isoformat(), # Send ISO UTC timestamp
                'sender_id': message.sender_id # Needed on client
            }
            room_name = get_room_name(message.sender_id, message.receiver_id)
            socketio.emit('message_deleted', deleted_message_data, room=room_name)
            print(f"[Delete Msg] Message {message_id} deleted for everyone by user {current_user.id}.")

    except Exception as e:
        # Rollback handled by 'with Session...'
        print(f"[Delete Msg] Error processing delete for message {message_id}: {e}")
        emit('delete_error', {'message_id': message_id, 'error': 'Server error during delete'}, room=request.sid)


@socketio.on('request_initial_counts')
def handle_request_initial_counts():
     if not current_user.is_authenticated: return
     user_id = current_user.id
     try:
         unread_counts_query = db.session.query(
             Message.sender_id,
             func.count(Message.id).label('unread_count')
         ).filter(
             Message.receiver_id == user_id,
             Message.seen == False,
             Message.deleted_for_everyone == False # Exclude deleted
         ).group_by(Message.sender_id).all()

         counts_map = {sender_id: count for sender_id, count in unread_counts_query}
         emit('initial_counts_response', counts_map) # Emit only to requesting user
     except Exception as e:
         print(f"[Initial Counts] Error querying counts for user {user_id}: {e}")
         emit('initial_counts_error', {'error': 'Could not fetch counts'})


# Add 'user_inactive' and 'user_active' handlers if needed, using chat app's current_user


# --- Main Execution ---
if __name__ == '__main__':
    print("Starting Chat Server...")
    # Use socketio.run() for development
    # For production, use gunicorn with eventlet or gevent worker
    # Example: gunicorn --worker-class eventlet -w 1 chat_server:app
    socketio.run(app, debug=True, host='0.0.0.0', port=5001) # Run on a different port than main app