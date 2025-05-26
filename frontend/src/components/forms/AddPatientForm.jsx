import React, { useState } from "react";
import "../../styles/AddPatientForm.css";
import { useNavigate } from 'react-router-dom';

function AddPatientForm({ token }) {
  token = token || localStorage.getItem("token");
  const navigate = useNavigate();
  const [form, setForm] = useState({
    name: "",
    age: "",
    picked_from: "",
    dropped_at: "",
    date: "",
    amount: "",
    driver: "",
  });
  const [message, setMessage] = useState("");
  const [isSuccess, setIsSuccess] = useState(false);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("");
    setIsSuccess(false);

    try {
      const response = await fetch("api/add-patient", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(form),
      });
      if (response.ok) {
        setMessage("Patient added successfully!");
        setIsSuccess(true);
        setForm({
          name: "",
          age: "",
          picked_from: "",
          dropped_at: "",
          date: "",
          amount: "",
          driver: "",
        });
        alert("Patient added successfully!");
        navigate('/');
      } else {
        const data = await response.json();
        setMessage(data.detail || "Failed to add patient.");
        setIsSuccess(false);
      }
    } catch (err) {
      setMessage("Error: " + err.message);
      setIsSuccess(false);
    }
  };

  return (
    <form className="form-container add-patient-form" onSubmit={handleSubmit}>
      <h2>Add Patient</h2>

      <div className="form-group">
        <label htmlFor="name">Name</label>
        <input name="name" id="name" placeholder="Name" value={form.name} onChange={handleChange} required />
      </div>

      <div className="form-group">
        <label htmlFor="age">Age</label>
        <input name="age" id="age" type="number" placeholder="Age" value={form.age} onChange={handleChange} required />
      </div>

      <div className="form-group">
        <label htmlFor="picked_from">Picked From</label>
        <input name="picked_from" id="picked_from" placeholder="Picked From" value={form.picked_from} onChange={handleChange} required />
      </div>

      <div className="form-group">
        <label htmlFor="dropped_at">Dropped At</label>
        <input name="dropped_at" id="dropped_at" placeholder="Dropped At" value={form.dropped_at} onChange={handleChange} required />
      </div>

      <div className="form-group">
        <label htmlFor="date">Date</label>
        <input name="date" id="date" type="date" placeholder="Date" value={form.date} onChange={handleChange} required />
      </div>

      <div className="form-group">
        <label htmlFor="amount">Amount</label>
        <input name="amount" id="amount" type="number" placeholder="Amount" value={form.amount} onChange={handleChange} required />
      </div>

      <div className="form-group">
        <label htmlFor="amount">Driver</label>
        <input name="driver" id="driver" type="text" placeholder="Driver" value={form.driver} onChange={handleChange} />
      </div>

      <button type="submit">Add Patient</button>

      {message && (
        <div className={`message ${isSuccess ? "success" : ""}`}><br />
          {message}
        </div>
      )}
    </form>
  );
}

export default AddPatientForm;
