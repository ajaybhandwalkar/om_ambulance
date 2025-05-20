import { useState } from 'react';
import axios from 'axios';
import '../styles/Login.css';

export default function Login({ setToken }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);

  const login = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setLoading(true);

    try {
      const response = await axios.post(
        '/api/token',
        new URLSearchParams({ username, password }),
        {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        }
      );

      const token = response.data.access_token;
      localStorage.setItem('token', token); // persist
      setToken(token); // trigger PatientDashboard
    } catch (error) {
      const status = error.response?.status;
      if (status === 401) {
        setErrorMsg('Incorrect password.');
      } else if (status === 404) {
        setErrorMsg('User not found.');
      } else if (status === 500) {
        setErrorMsg('Server error. Please try again later.');
      } else {
        setErrorMsg('Unexpected error. Check your connection.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <form className="login-form" onSubmit={login}>
        <h2>Login</h2>
        <input
          type="text"
          placeholder="Username"
          value={username}
          required
          onChange={(e) => setUsername(e.target.value)}
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          required
          onChange={(e) => setPassword(e.target.value)}
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Logging in...' : 'Login'}
        </button>
        {errorMsg && <p className="error">{errorMsg}</p>}
      </form>
    </div>
  );
}
