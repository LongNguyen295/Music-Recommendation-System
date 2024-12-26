import React, { useState, useEffect } from "react";
import {
  Container,
  TextField,
  Button,
  Typography,
  CircularProgress,
  Box,
  Modal,
  Table,
  TableHead,
  TableRow,
  TableCell,
  TableBody,
  TableContainer,
  Paper,
  Alert,
} from "@mui/material";
import { PlayArrow, Search, History, QueueMusic } from "@mui/icons-material";
import "./App.css";

const App = () => {
  const [songName, setSongName] = useState("");
  const [results, setResults] = useState([]);
  const [history, setHistory] = useState([]);
  const [recommendations, setRecommendations] = useState([]);
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [currentVideoId, setCurrentVideoId] = useState(null);
  const [openModal, setOpenModal] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [registerUsername, setRegisterUsername] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [registerConfirmPassword, setRegisterConfirmPassword] = useState("");
  const [isRegistering, setIsRegistering] = useState(false); // Thêm trạng thái đăng ký
  const [role, setRole] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token && isLoggedIn) {
      if (role === "admin") {
        fetchUsers();
      } else {
        fetchHistory();
        fetchRecommendations();
      }
    } else if (!token && isLoggedIn) {
      setIsLoggedIn(false);
      setRole("");
    }

    return () => {
      setUsers([]);
      setHistory([]);
      setRecommendations([]);
    };
  }, [isLoggedIn, role]);

  const fetchHistory = async (page = 1, limit = 5) => {
    try {
      const response = await fetch(`http://127.0.0.1:5000/history?page=${page}&limit=${limit}`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      });
      const data = await response.json();
      if (!data.error) {
        setHistory(data.history);
        setTotalPages(data.total_pages); // Cập nhật tổng số trang
        setCurrentPage(page); // Lưu trang hiện tại
      } else {
        setError(data.error);
      }
    } catch {
      setError("Unable to fetch listening history. Please try again later.");
    }
  };  

  const fetchRecommendations = async () => {
    try {
      const response = await fetch(
        "http://127.0.0.1:5000/recommend-from-history",
        {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        }
      );
      const data = await response.json();
      if (!data.error) {
        setRecommendations(data.tracks);
      } else {
        setError(data.error);
      }
    } catch {
      setError("Unable to fetch recommendations. Please try again later.");
    }
  };

  const fetchUsers = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        setError("Please login again");
        setIsLoggedIn(false);
        return;
      }
  
      const response = await fetch("http://127.0.0.1:5000/users", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      });
  
      if (response.ok) {
        const data = await response.json();
        setUsers(data);
        setError("");
      } else {
        const errorData = await response.json();
        setError(errorData.error || "Failed to fetch users list");
      }
    } catch (error) {
      setError("Error loading users list");
    }
  };  

  const deleteUser = async (username) => {
    const confirmDelete = window.confirm(
      `Are you sure you want to delete user '${username}'?`
    );
    if (!confirmDelete) return;
  
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        setError("Please login again");
        setIsLoggedIn(false);
        return;
      }
  
      const response = await fetch(`http://127.0.0.1:5000/delete-user/${username}`, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      });
  
      if (response.ok) {
        setError("");
        alert(`User '${username}' has been deleted successfully.`);
        fetchUsers(); // Refresh the user list
      } else {
        const errorData = await response.json();
        setError(errorData.error || "Failed to delete user.");
      }
    } catch (error) {
      setError("Error deleting user.");
    }
  };
  

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!songName.trim()) {
      setError("Please enter a valid song name.");
      return;
    }
  
    setLoading(true);
    try {
      const response = await fetch("http://127.0.0.1:5000/recommend", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
        body: JSON.stringify({ name: songName }),
      });
  
      const data = await response.json();
  
      if (!response.ok) {
        // Hiển thị lỗi từ backend
        setError(data.error || "Unable to fetch recommendations.");
        setResults([]);
      } else {
        // Nếu thành công, hiển thị kết quả
        setResults(data.tracks);
        setError(""); // Xóa lỗi nếu có
      }
    } catch {
      setError("Unable to connect to the server. Please try again later.");
      setResults([]);
    }
    setLoading(false);
  };
  

  const saveAndOpenYouTube = async (name, artist, videoId = null) => {
    try {
      const songData = { name, artist, videoId };

      const response = await fetch("http://127.0.0.1:5000/play", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
        body: JSON.stringify(songData),
      });

      if (!response.ok) {
        throw new Error("Failed to save song to history.");
      }

      setHistory((prevHistory) => {
        const exists = prevHistory.some(
          (item) =>
            item.name === songData.name && item.artist === songData.artist
        );
        return exists ? prevHistory : [...prevHistory, songData];
      });

      setCurrentVideoId(videoId);
      setOpenModal(true);
    } catch (error) {
      alert("Error saving song to history: " + error.message);
    }
  };

  // Xử lý đăng ký
  const handleRegister = async (e) => {
    e.preventDefault();
    setError("");
  
    if (!registerUsername || !registerPassword || !registerConfirmPassword) {
      setError("All fields are required.");
      return;
    }
  
    if (registerPassword !== registerConfirmPassword) {
      setError("Passwords do not match.");
      return;
    }
  
    try {
      const response = await fetch("http://127.0.0.1:5000/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: registerUsername,
          password: registerPassword,
          confirm_password: registerConfirmPassword,
        }),
      });
  
      const data = await response.json();
  
      if (response.ok) {
        setError("");
        alert("Registration successful. Please log in.");
        setIsRegistering(false); // Quay lại màn hình đăng nhập
      } else {
        setError(data.error || "Registration failed.");
      }
    } catch (error) {
      console.error("Registration error:", error);
      setError("Network error. Please try again.");
    }
  };
  
  

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");

    if (!username || !password) {
      setError("Username and password are required.");
      return;
    }

    try {
      const response = await fetch("http://127.0.0.1:5000/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (response.ok) {
        localStorage.setItem("token", data.token);
        setRole(data.role);
        setIsLoggedIn(true);
        setError("");
      } else {
        setError(data.error || "Login failed");
        setIsLoggedIn(false);
      }
    } catch (error) {
      console.error("Login error:", error);
      setError("Network error. Please try again.");
      setIsLoggedIn(false);
    }
  };

  const handleLogout = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        localStorage.removeItem("token");
        setIsLoggedIn(false);
        setUsername("");
        setPassword("");
        setRole("");
        setUsers([]);
        setResults([]);
        setHistory([]);
        setRecommendations([]);
        return;
      }

      const response = await fetch("http://127.0.0.1:5000/logout", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      });

      localStorage.removeItem("token");
      setIsLoggedIn(false);
      setUsername("");
      setPassword("");
      setRole("");
      setUsers([]);
      setResults([]);
      setHistory([]);
      setRecommendations([]);

      if (!response.ok) {
        console.error("Logout failed on server side");
      }
    } catch (error) {
      console.error("Logout error:", error);
      localStorage.removeItem("token");
      setIsLoggedIn(false);
      setUsername("");
      setPassword("");
      setRole("");
      setUsers([]);
      setResults([]);
      setHistory([]);
      setRecommendations([]);
    }
  };

  const renderLoginForm = () => (
    <form onSubmit={handleLogin}>
      <Typography variant="h5" gutterBottom>
        Login
      </Typography>
      {error && <Alert severity="error">{error}</Alert>}
      <TextField
        label="Username"
        fullWidth
        margin="normal"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <TextField
        label="Password"
        type="password"
        fullWidth
        margin="normal"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <Button type="submit" variant="contained" color="primary">
        Login
      </Button>
      <Button
        variant="text"
        color="secondary"
        onClick={() => setIsRegistering(true)}
      >
        Create an Account
      </Button>
    </form>
  );
  

  
  const renderRegisterForm = () => (
    <form onSubmit={handleRegister}>
      <Typography variant="h5" gutterBottom>
        Register
      </Typography>
      {error && <Alert severity="error">{error}</Alert>}
      <TextField
        label="Username"
        fullWidth
        margin="normal"
        value={registerUsername}
        onChange={(e) => setRegisterUsername(e.target.value)}
      />
      <TextField
        label="Password"
        type="password"
        fullWidth
        margin="normal"
        value={registerPassword}
        onChange={(e) => setRegisterPassword(e.target.value)}
      />
      <TextField
        label="Confirm Password"
        type="password"
        fullWidth
        margin="normal"
        value={registerConfirmPassword}
        onChange={(e) => setRegisterConfirmPassword(e.target.value)}
      />
      <Button type="submit" variant="contained" color="primary">
        Register
      </Button>
      <Button
        variant="text"
        color="secondary"
        onClick={() => setIsRegistering(false)}
      >
        Back to Login
      </Button>
    </form>
  );
  

  const renderUserList = () => (
    <Box my={4}>
      <Typography variant="h5" gutterBottom>
        User List
      </Typography>
      {error && <Alert severity="error">{error}</Alert>}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Username</TableCell>
              <TableCell>Role</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {users.map((user, index) => (
              <TableRow key={index}>
                <TableCell>{user.username}</TableCell>
                <TableCell>{user.role}</TableCell>
                <TableCell align="right">
                  <Button
                    variant="outlined"
                    color="error"
                    onClick={() => deleteUser(user.username)}
                  >
                    Delete
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );  
  
  const renderPagination = () => (
    <Box display="flex" justifyContent="center" mt={2}>
      <Button
        variant="outlined"
        color="primary"
        disabled={currentPage === 1}
        onClick={() => fetchHistory(currentPage - 1)}
      >
        Previous
      </Button>
      <Typography variant="body1" mx={2}>
        Page {currentPage} of {totalPages}
      </Typography>
      <Button
        variant="outlined"
        color="primary"
        disabled={currentPage === totalPages}
        onClick={() => fetchHistory(currentPage + 1)}
      >
        Next
      </Button>
    </Box>
  );

  const renderSongList = (songs, title, emptyMessage, icon, enablePagination = false) => (
    <Box my={4}>
      <Typography variant="h5" gutterBottom>
        {icon} {title}
      </Typography>
      {songs.length === 0 ? (
        <Typography variant="body2" color="textSecondary">
          {emptyMessage}
        </Typography>
      ) : (
        <>
          <Box>
            {songs.map((song, index) => (
              <Box
                key={index}
                display="flex"
                alignItems="center"
                justifyContent="space-between"
                p={2}
                borderBottom="1px solid #ddd"
              >
                {/* Song Details */}
                <Box>
                  <Typography
                    variant="h6"
                    className="song-name"
                    title={song.name}
                  >
                    {song.name}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Artist: {song.artist || song.artists}
                  </Typography>
                </Box>
  
                {/* Play or Search Button */}
                <Box>
                  {song.videoId ? (
                    <Button
                      variant="contained"
                      color="primary"
                      startIcon={<PlayArrow />}
                      onClick={() =>
                        saveAndOpenYouTube(
                          song.name,
                          song.artist || song.artists,
                          song.videoId
                        )
                      }
                    >
                      Play on YouTube
                    </Button>
                  ) : (
                    <Button
                      variant="outlined"
                      color="secondary"
                      startIcon={<Search />}
                      onClick={() =>
                        saveAndOpenYouTube(song.name, song.artist || song.artists)
                      }
                    >
                      Search on YouTube
                    </Button>
                  )}
                </Box>
              </Box>
            ))}
          </Box>
          {/* Pagination Controls */}
          {enablePagination && renderPagination()}
        </>
      )}
    </Box>
  );    

  return (
    <Container>
      <Box py={4} textAlign="center" className="header">
        <Typography variant="h3" gutterBottom>
          🎵 Music Recommendation System
        </Typography>
        {isLoggedIn && (
          <Button
            variant="outlined"
            color="secondary"
            onClick={handleLogout}
            style={{ position: "absolute", right: "20px", top: "20px" }}
          >
            Logout
          </Button>
        )}
      </Box>
  
      {!isLoggedIn ? (
        <Box>{isRegistering ? renderRegisterForm() : renderLoginForm()}</Box>
      ) : (
        <>
          {role === "admin" ? (
            renderUserList()
          ) : (
            <>
              <Box>
                <form onSubmit={handleSubmit}>
                  <TextField
                    label="Search for a song"
                    fullWidth
                    margin="normal"
                    value={songName}
                    onChange={(e) => setSongName(e.target.value)}
                  />
                  <Button type="submit" variant="contained" color="primary">
                    Search
                  </Button>
                </form>
              </Box>
              {loading && (
                <Box my={2} textAlign="center">
                  <CircularProgress />
                </Box>
              )}
              {error && (
                <Box my={2}>
                  <Alert severity="error">{error}</Alert>
                </Box>
              )}
              {!loading && results.length > 0 && (
                renderSongList(
                  results,
                  "Search Results",
                  "No songs found.",
                  <Search />,
                  false // Không phân trang cho Search Results
                )
              )}
              {renderSongList(
                history,
                "Listening History",
                "No songs in history yet.",
                <History />,
                true // Phân trang cho Listening History
              )}
              {renderSongList(
                recommendations,
                "Recommendations Based on History",
                "No recommendations available.",
                <QueueMusic />,
                false // Không phân trang cho Recommendations
              )}
            </>
          )}
        </>
      )}
  
      <Modal
        open={openModal}
        onClose={() => setOpenModal(false)}
        aria-labelledby="youtube-video-modal"
        aria-describedby="play-video-in-modal"
      >
        <Box
          sx={{
            position: "absolute",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            width: "80%",
            maxWidth: 800,
            bgcolor: "background.paper",
            boxShadow: 24,
            p: 4,
            borderRadius: 2,
          }}
        >
          <iframe
            width="100%"
            height="450"
            src={`https://www.youtube.com/embed/${currentVideoId}`}
            title="YouTube video player"
            frameBorder="0"
            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
            allowFullScreen
          />
          <Box mt={2} display="flex" justifyContent="flex-end">
            <Button variant="contained" onClick={() => setOpenModal(false)}>
              Close
            </Button>
          </Box>
        </Box>
      </Modal>
    </Container>
  );  
    
};

export default App;
