from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import logging
import os
import pickle
import pandas as pd
import numpy as np
from scipy.spatial.distance import cdist
from googleapiclient.discovery import build
from bson.objectid import ObjectId
from functools import wraps
import secrets

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

# Logging setup
logging.basicConfig(level=logging.INFO)

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['music_recommendation']

# Flask-Login setup
app.secret_key = os.urandom(24)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, username, password, role, user_id):
        self.username = username
        self.password = password
        self.role = role
        self.user_id = user_id

    def get_id(self):
        return str(self.user_id)

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(username=user_data['username'], password=user_data['password'], role=user_data['role'], user_id=user_data['_id'])
    return None

# YouTube API configuration
YOUTUBE_API_KEYS = [
    "AIzaSyDgqq-jV1cfT9LSIg1PJqrSRKBAT2U-FuU",
    "AIzaSyDBacE7mLpANhStgPD2tr6Z7K7Q1eRHbIU",
    "AIzaSyCA3M0mu3CFvr88IgsG3ksG1YVzyPxcuII",
    "AIzaSyBhUF10GMkPTPsYS0j1CgBM7dE5uhfPOPE",
    "AIzaSyA4jKr513wBcMtmfN_taJhWtZYiOuKU0Yw",
    "AIzaSyCpj5o4tKckyR_AinOSaM_IWEwt94LcLhk"
]

current_api_index = 0
youtube = build("youtube", "v3", developerKey=YOUTUBE_API_KEYS[current_api_index])

# Load model and scaler
try:
    with open("kmeans_model.pkl", "rb") as f:
        kmeans = pickle.load(f)

    with open("scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
except FileNotFoundError as e:
    raise FileNotFoundError("Model file not found. Ensure 'kmeans_model.pkl' and 'scaler.pkl' exist.") from e

# Load data
data_path = "./data.csv"
if not os.path.exists(data_path):
    raise FileNotFoundError(f"Data file not found: {data_path}")

data = pd.read_csv(data_path)
number_cols = ['valence', 'danceability', 'energy', 'acousticness',
               'instrumentalness', 'liveness', 'loudness',
               'speechiness', 'tempo', 'popularity']

# Initialize collections
HISTORY_COLLECTION = db['history']
USER_COLLECTION = db['users']

def create_admin_account():
    """Create an admin account if it doesn't exist."""
    admin_username = "admin"
    admin_password = generate_password_hash("123")  # Change for security

    if not USER_COLLECTION.find_one({"username": admin_username}):
        USER_COLLECTION.insert_one({"username": admin_username, "password": admin_password, "role": "admin"})
        logging.info("Admin account created.")
    else:
        logging.info("Admin account already exists.")

create_admin_account()

def save_to_history(username, song_name, artist_name, video_id):
    """Save song to listening history with YouTube video ID."""
    try:
        # Kiểm tra nếu bài hát đã tồn tại trong lịch sử của user
        if HISTORY_COLLECTION.find_one({"username": username, "name": song_name, "artist": artist_name}):
            logging.info(f"Song '{song_name}' by '{artist_name}' is already in history for user '{username}'.")
            return

        # Lưu bài hát vào lịch sử
        HISTORY_COLLECTION.insert_one({
            "username": username,
            "name": song_name,
            "artist": artist_name,
            "videoId": video_id,
            "timestamp": datetime.now().isoformat()
        })
        logging.info(f"Saved to history: {song_name} by {artist_name} for user {username}")
    except Exception as e:
        logging.error(f"Unexpected error in save_to_history: {e}")


def get_history(username):
    """Retrieve listening history for a user."""
    try:
        return list(HISTORY_COLLECTION.find({"username": username}))
    except Exception as e:
        logging.error(f"Unexpected error in get_history: {e}")
        return []

def get_youtube_video(song_name):
    """Fetch video details from YouTube API."""
    global current_api_index
    for _ in range(len(YOUTUBE_API_KEYS)):
        try:
            youtube = build("youtube", "v3", developerKey=YOUTUBE_API_KEYS[current_api_index])
            search_response = youtube.search().list(
                q=song_name,
                part="snippet",
                type="video",
                maxResults=1
            ).execute()

            video_id = search_response['items'][0]['id']['videoId']
            video_title = search_response['items'][0]['snippet']['title']
            return {
                "name": video_title,
                "videoId": video_id
            }
        except Exception as e:
            logging.error(f"Error fetching YouTube video with API key {YOUTUBE_API_KEYS[current_api_index]}: {e}")
            current_api_index = (current_api_index + 1) % len(YOUTUBE_API_KEYS)
    
    logging.error("All YouTube API keys exhausted.")
    return None

@app.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')  # Thêm xác nhận mật khẩu

    if not username or not password or not confirm_password:
        return jsonify({"error": "All fields are required."}), 400

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400

    if USER_COLLECTION.find_one({"username": username}):
        return jsonify({"error": "Username already exists."}), 400

    hashed_password = generate_password_hash(password)

    try:
        USER_COLLECTION.insert_one({"username": username, "password": hashed_password, "role": "user"})
        return jsonify({"message": "User registered successfully."}), 201
    except Exception as e:
        logging.error(f"Error registering user: {e}")
        return jsonify({"error": "An error occurred while registering the user."}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
        
    user = db.users.find_one({"username": username})
    
    if user and check_password_hash(user['password'], password):
        # Generate new token
        token = secrets.token_hex(32)
        # Update token in database
        db.users.update_one(
            {"username": username},
            {"$set": {"token": token}}
        )
        
        return jsonify({
            "token": token,
            "role": user.get('role', 'user'),
            "username": username
        }), 200
    
    return jsonify({"error": "Invalid username or password"}), 401

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Token is missing or invalid. Format should be "Bearer <token>".'}), 401

        if not token:
            return jsonify({'error': 'Token is missing. Please log in again.'}), 401

        try:
            user = USER_COLLECTION.find_one({"token": token})
            if not user:
                return jsonify({'error': 'Invalid or expired token. Please log in again.'}), 401
            g.current_user = user
            return f(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in token_required: {e}")
            return jsonify({'error': 'An error occurred while verifying the token.'}), 401

    return decorated

@app.route('/logout', methods=['POST'])
@token_required
def logout():
    """Logout the current user."""
    try:
        token = request.headers.get('Authorization').split()[1]
        result = db.users.update_one(
            {"token": token},
            {"$unset": {"token": ""}}
        )
        if result.modified_count == 0:
            return jsonify({"error": "Invalid or expired token. Please log in again."}), 401

        return jsonify({"message": "Logged out successfully."}), 200
    except Exception as e:
        logging.error(f"Error during logout: {e}")
        return jsonify({"error": "An error occurred during logout. Please try again."}), 500


@app.route('/users', methods=['GET'])
@token_required
def get_users():
    try:
        # Lấy user từ context đã được set trong token_required
        current_user = g.current_user
        
        if not current_user or current_user.get('role') != 'admin':
            return jsonify({"error": "Unauthorized access"}), 403

        users = list(USER_COLLECTION.find({}, {"_id": 0, "password": 0, "token": 0}))
        return jsonify(users), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/delete-user/<string:username>', methods=['DELETE'])
@token_required
def delete_user(username):
    """Allow admin to delete a user account."""
    try:
        # Lấy thông tin user hiện tại từ token
        current_user = g.current_user

        # Chỉ cho phép admin thực hiện
        if not current_user or current_user.get('role') != 'admin':
            return jsonify({"error": "Unauthorized access"}), 403

        # Không cho phép admin tự xóa chính mình
        if current_user['username'] == username:
            return jsonify({"error": "Admin cannot delete their own account."}), 400

        # Tìm và xóa user trong cơ sở dữ liệu
        result = USER_COLLECTION.delete_one({"username": username})

        if result.deleted_count == 0:
            return jsonify({"error": f"User '{username}' not found."}), 404

        return jsonify({"message": f"User '{username}' deleted successfully."}), 200
    except Exception as e:
        logging.error(f"Error in /delete-user: {e}")
        return jsonify({"error": "An error occurred while deleting the user."}), 500


@app.route('/recommend', methods=['POST'])
@token_required
def recommend():
    """Recommend songs based on input."""
    try:
        request_data = request.json
        song_name = request_data.get('name', None)

        if not song_name:
            return jsonify({"error": "Song name is required."}), 400

        # Tìm bài hát trong dữ liệu
        local_matches = data[data['name'].str.lower() == song_name.lower()]

        if local_matches.empty:
            # Trả thông báo khi không tìm thấy bài hát
            return jsonify({"error": f"Song '{song_name}' is not in the training data."}), 404

        # Xử lý nếu bài hát tồn tại
        song_vector = local_matches.iloc[0][number_cols].values
        scaled_song_center = scaler.transform([song_vector])
        cluster_label = kmeans.predict(scaled_song_center)[0]
        cluster_data = data[kmeans.labels_ == cluster_label]
        scaled_cluster_data = scaler.transform(cluster_data[number_cols])

        distances = cdist(scaled_song_center, scaled_cluster_data, 'cosine')
        indices = np.argsort(distances[0])[:5]

        recommendations = cluster_data.iloc[indices][['name', 'year', 'artists']].to_dict(orient='records')

        # Lấy video ID từ YouTube cho từng bài hát
        for rec in recommendations:
            youtube_data = get_youtube_video(f"{rec['name']} {rec['artists']}")
            rec["videoId"] = youtube_data.get("videoId")

        return jsonify({"tracks": recommendations})
    except Exception as e:
        logging.error(f"Error in /recommend: {e}")
        return jsonify({"error": f"Failed to recommend songs: {str(e)}"}), 500


@app.route('/play', methods=['POST'])
@token_required
def play_song():
    """Handle song playback and save to history."""
    try:
        data = request.json
        song_name = data.get('name')
        artist_name = data.get('artist')

        youtube_data = get_youtube_video(f"{song_name} {artist_name}")
        if not youtube_data:
            return jsonify({"error": "Could not find video."}), 404

        video_id = youtube_data['videoId']
        save_to_history(g.current_user['username'], song_name, artist_name, video_id)

        return jsonify({"message": "Song saved to history", "videoId": video_id}), 200
    except Exception as e:
        logging.error(f"Error in /play: {e}")
        return jsonify({"error": f"Failed to save song: {str(e)}"}), 500


@app.route('/history', methods=['GET'])
@token_required
def history():
    """Return paginated listening history for the current user."""
    try:
        username = g.current_user['username']
        
        # Lấy tham số phân trang từ query string
        page = int(request.args.get('page', 1))  # Mặc định là trang 1
        limit = int(request.args.get('limit', 5))  # Mặc định 5 bài trên 1 trang

        # Tính toán offset
        skip = (page - 1) * limit

        # Lấy lịch sử theo thứ tự từ mới đến cũ
        user_history = list(HISTORY_COLLECTION.find(
            {"username": username},
            {"_id": 0, "username": 0}
        ).sort("timestamp", -1).skip(skip).limit(limit))

        # Đếm tổng số bài trong lịch sử
        total_count = HISTORY_COLLECTION.count_documents({"username": username})

        # Trả về dữ liệu phân trang
        return jsonify({
            "history": user_history,
            "total": total_count,
            "page": page,
            "limit": limit,
            "total_pages": (total_count + limit - 1) // limit  # Tính số trang
        }), 200
    except Exception as e:
        logging.error(f"Error in /history: {e}")
        return jsonify({"error": "Failed to fetch history."}), 500

@app.route('/recommend-from-history', methods=['GET'])
@token_required
def recommend_from_history():
    """Recommend songs based on listening history."""
    try:
        username = g.current_user['username']
        # Lấy lịch sử nghe gần nhất (tối đa 5 bài gần nhất)
        history = list(HISTORY_COLLECTION.find(
            {"username": username},
            {"_id": 0, "name": 1, "artist": 1}
        ).sort("timestamp", -1).limit(5))

        if not history:
            return jsonify({"error": "No history found"}), 404

        all_recommendations = []
        for song in history:
            local_matches = data[data['name'].str.lower() == song['name'].lower()]
            if not local_matches.empty:
                song_vector = local_matches.iloc[0][number_cols].values
                scaled_song_center = scaler.transform([song_vector])
                cluster_label = kmeans.predict(scaled_song_center)[0]
                cluster_data = data[kmeans.labels_ == cluster_label]
                scaled_cluster_data = scaler.transform(cluster_data[number_cols])
                distances = cdist(scaled_song_center, scaled_cluster_data, 'cosine')
                indices = np.argsort(distances[0])[:5]
                all_recommendations.extend(cluster_data.iloc[indices][['name', 'year', 'artists']].to_dict(orient='records'))

        # Loại bỏ trùng lặp trong danh sách đề xuất
        unique_recommendations = {rec['name']: rec for rec in all_recommendations}.values()

        # Giới hạn danh sách chỉ trả về 5 bài hát giống nhất
        limited_recommendations = list(unique_recommendations)[:5]

        # Lấy YouTube video ID cho từng bài hát
        for rec in limited_recommendations:
            youtube_data = get_youtube_video(f"{rec['name']} {rec['artists']}")
            rec["videoId"] = youtube_data.get("videoId")

        return jsonify({"tracks": limited_recommendations})
    except Exception as e:
        logging.error(f"Error in /recommend-from-history: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
