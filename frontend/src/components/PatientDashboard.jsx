import { useEffect, useState } from 'react';
import axios from 'axios';

export default function PatientDashboard({ token }) {
  const [patients, setPatients] = useState([]);
  const [error, setError] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const rowsPerPage = 10;
  const [totalCount, setTotalCount] = useState(0);

  // Form inputs for filtering
  const [filters, setFilters] = useState({
    name: '',
    picked_from: '',
    dropped_at: '',
    date: '',
    from_date: '',
    to_date: ''
  });

  // Fetch patients (with all data)
  const fetchPatients = async () => {
    setError('');
    const payload = {};

    // Add filter criteria to the request
    for (const key in filters) {
      if (filters[key]?.trim() !== '') {
        payload[key] = filters[key];
      }
    }

    try {
      const response = await axios.post(
        '/api/get-search_criteria',
        payload,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );

      // Assuming the response contains all patient data
      setPatients(response.data.patient_search_criteria || []);
      setTotalCount(response.data.patient_search_criteria.length);  // Use length of the full data for pagination
    } catch (err) {
      console.error(err);
      setError('Failed to fetch patient data.');
    }
  };

  useEffect(() => {
    fetchPatients();
  }, [filters]); // Re-run when filters change

  const handleChange = (e) => {
    const { name, value } = e.target;
    if (name === 'date' || name === 'from_date' || name === 'to_date') {
      setFilters({
        ...filters,
        [name]: value.includes('T') ? value : `${value}T00:00`,
      });
    } else {
      setFilters({ ...filters, [name]: value });
    }
  };

  // Handle filter form submission
  const handleSubmit = (e) => {
    e.preventDefault();
    setCurrentPage(1); // Reset to first page on new search
    fetchPatients();
  };

  // Pagination logic
  const totalPages = Math.ceil(totalCount / rowsPerPage);  // Calculate total pages based on the totalCount of patients
  const startIdx = (currentPage - 1) * rowsPerPage;
  const currentRows = patients.slice(startIdx, startIdx + rowsPerPage);  // Slice the patients array to get the current page's data

  const handlePrev = () => {
    setCurrentPage((prev) => Math.max(prev - 1, 1));  // Don't go below page 1
  };

  const handleNext = () => {
    setCurrentPage((prev) => Math.min(prev + 1, totalPages));  // Don't go beyond total pages
  };

  return (
    <div className="dashboard-container">
      <h2 className="dashboard-title">Patient List</h2>

      {/* Filter Form */}
      <form onSubmit={handleSubmit} className="filter-form">
        <input
          name="name"
          placeholder="Name"
          value={filters.name}
          onChange={handleChange}
          className="filter-input"
        />
        <input
          name="picked_from"
          placeholder="Picked From"
          value={filters.picked_from}
          onChange={handleChange}
          className="filter-input"
        />
        <input
          name="dropped_at"
          placeholder="Dropped At"
          value={filters.dropped_at}
          onChange={handleChange}
          className="filter-input"
        />
        <input
          name="date"
          type="datetime-local"
          value={filters.date}
          onChange={handleChange}
          className="filter-input"
        />
        <input
          name="from_date"
          type="datetime-local"
          value={filters.from_date}
          onChange={handleChange}
          className="filter-input"
        />
        <input
          name="to_date"
          type="datetime-local"
          value={filters.to_date}
          onChange={handleChange}
          className="filter-input"
        />
        <button type="submit" className="filter-submit-btn">Search</button>
      </form>

      {/* Error */}
      {error && <p className="error-message">{error}</p>}

      {/* Table of Patients */}
      <table className="patient-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Picked From</th>
            <th>Dropped At</th>
            <th>Date</th>
            <th>Age</th>
            <th>Driver</th>
            <th>Amount</th>
          </tr>
        </thead>
        <tbody>
          {currentRows.length > 0 ? (
            currentRows.map((p) => (
              <tr key={p.id}>
                <td>{p.id}</td>
                <td>{p.name}</td>
                <td>{p.picked_from}</td>
                <td>{p.dropped_at}</td>
                <td>{p.date}</td>
                <td>{p.age}</td>
                <td>{p.driver}</td>
                <td>{p.amount}</td>
              </tr>
            ))
          ) : (
            <tr><td colSpan="8">No patients found.</td></tr>
          )}
        </tbody>
      </table>

      {/* Pagination Controls */}
      <div className="pagination-controls">
        <button onClick={handlePrev} disabled={currentPage === 1} className="pagination-btn">
          Previous
        </button>
        <span className="pagination-text">Page {currentPage} of {totalPages}</span>
        <button onClick={handleNext} disabled={currentPage === totalPages} className="pagination-btn">
          Next
        </button>
      </div>
    </div>
  );
}
