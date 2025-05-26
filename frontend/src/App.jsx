import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import PatientDashboard from './components/PatientDashboard';
import Header from './components/Header';
import Footer from './components/Footer';
import AddPatientForm from './components/forms/AddPatientForm';
import RegisterUserForm from './components/forms/RegisterUserForm';
import UpdatePatientForm from './components/forms/UpdatePatientForm';

export default function App() {
  const [token, setToken] = useState('');

  const handleLogout = () => {
    setToken('');
  };

  // Protect routes that require authentication
  const PrivateRoute = ({ children }) => {
    if (!token) {
      return <Navigate to="/" replace />; // Redirect to Login if no token
    }
    return children; // Allow access to the route if token exists
  };

  return (
    <Router>
      <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
        {/* Header will always show */}
        <Header onLogout={handleLogout} showButtons={!!token} />

        <main style={{ flex: 1, padding: '20px' }}>
          {/* Routes for login, dashboard, and other forms */}
          <Routes>
            {/* Route for Login (default page if no token) */}
            <Route path="/" element={!token ? <Login setToken={setToken} /> : <PatientDashboard token={token} />} />

            {/* Protected Routes */}
            <Route path="/add-patient" element={<PrivateRoute><AddPatientForm /></PrivateRoute>} />
            <Route path="/register-user" element={<PrivateRoute><RegisterUserForm /></PrivateRoute>} />
            <Route path="/login" element={<PrivateRoute><Login /></PrivateRoute>} />
            <Route path="/patient-dashboard" element={<PrivateRoute><PatientDashboard /></PrivateRoute>} />
            <Route path="/update-patient" element={<PrivateRoute><UpdatePatientForm /></PrivateRoute>} />
          </Routes>
        </main>

        <Footer />
      </div>
    </Router>
  );
}





