import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import '../../styles/RegisterUserForm.css'; // Assuming your CSS file is being imported

export default function RegisterUserForm() {  // Pass token as a prop
  const [name, setName] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const [timeLeft, setTimeLeft] = useState(5);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setErrorMessage('');

    // Create the user object to send to the backend
    const userData = { name, username, password };
    const token = localStorage.getItem('token');

    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

    try {
      // Post request with token in the Authorization header
      const response = await axios.post('api/register', userData, {
        headers: {
          Authorization: `Bearer ${token}`,  // Use the token passed as prop
          'Content-Type': 'application/json', // Ensure content type is set correctly
        },
      });

      // Handle successful registration
      alert(response.data.msg);  // You can display a success message
      navigate('/');  // Redirect to login or dashboard after successful registration
    } catch (error) {
      // Handle errors based on status code or general error
      if (error.response && error.response.status === 409) {
        setErrorMessage('Username already exists.');
      } else if (error.response && error.response.status === 403) {
        setErrorMessage('Only owners can register users.');
      } else if (error.response && error.response.status === 401) {
        setErrorMessage('Session expired redirecting to Login')
        await sleep(3000);
        navigate("/login")
      } else {
        setErrorMessage('An error occurred. Please try again later.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="form-container">
      <h2>Register New User</h2>
      {errorMessage && <p className="error-message">{errorMessage}</p>}
      <form onSubmit={handleSubmit} className="register-user-form">
        <div className="form-group">
          <label htmlFor="name">Name</label>
          <input
            type="text"
            id="name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <div>
          <button type="submit" disabled={loading}>
            {loading ? 'Registering...' : 'Register'}
          </button>
        </div>
      </form>
    </div>
  );
}
