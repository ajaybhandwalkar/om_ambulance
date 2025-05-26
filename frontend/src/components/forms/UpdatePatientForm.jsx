import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";

function UpdatePatientForm() {
    const navigate = useNavigate();
    const location = useLocation();

    // Get patient object and token from location.state
    const { patient, token } = location.state || {};

    if (!patient || !token) {
        return <p>Error: patient or token missing in navigation state.</p>;
    }

    const patientId = patient.id; // Fix: get id for API calls
    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

    const [formData, setFormData] = useState({
        name: patient.name || "",
        age: patient.age || "",
        picked_from: patient.picked_from || "",
        dropped_at: patient.dropped_at || "",
        date: patient.date ? patient.date.split("T")[0] : "", // extract date part if datetime
        amount: patient.amount || "",
        driver: patient.driver || "",
    });

    const [originalData] = useState(formData);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData((prev) => ({ ...prev, [name]: value }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        // Patch only changed fields
        const patchData = {};
        for (const key in formData) {
            if (formData[key] !== originalData[key]) {
                patchData[key] = formData[key];
            }
        }

        if (Object.keys(patchData).length === 0) {
            alert("No changes detected.");
            return;
        }

        try {
            const res = await fetch(`api/update-patient?patient_id=${patient.id}`, {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(patchData),
            });

            if (!res.ok) {
                const errText = await res.text();
                throw new Error(errText || "Failed to update patient");
            }

            // Redirect after success, maybe back to dashboard or patient details
            alert("Patient updated successfully!");

            navigate(`/`, { state: { token } });
        } catch (err) {
            alert("Error updating patient: " + err.message);
        }
    };

    return (
        <div className="form-container">
            <h2>Update Patient</h2>
            <form onSubmit={handleSubmit} className="add-patient-form">
                <div className="form-group">
                    <label htmlFor="name">Name:</label>
                    <input
                        id="name"
                        name="name"
                        value={formData.name}
                        onChange={handleChange}
                        required
                        type="text"
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="age">Age:</label>
                    <input
                        id="age"
                        type="number"
                        name="age"
                        value={formData.age}
                        onChange={handleChange}
                        min="0"
                        required
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="picked_from">Picked From:</label>
                    <input
                        id="picked_from"
                        name="picked_from"
                        value={formData.picked_from}
                        onChange={handleChange}
                        type="text"
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="dropped_at">Dropped At:</label>
                    <input
                        id="dropped_at"
                        name="dropped_at"
                        value={formData.dropped_at}
                        onChange={handleChange}
                        type="text"
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="date">Date:</label>
                    <input
                        id="date"
                        type="date"
                        name="date"
                        value={formData.date}
                        onChange={handleChange}
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="amount">Amount:</label>
                    <input
                        id="amount"
                        type="number"
                        name="amount"
                        value={formData.amount}
                        onChange={handleChange}
                        min="0"
                        step="0.01"
                    />
                </div>

                <div className="form-group">
                    <label htmlFor="driver">Driver ID:</label>
                    <input
                        id="driver"
                        name="driver"
                        value={formData.driver}
                        onChange={handleChange}
                        type="text"
                    />
                </div>

                <button type="submit">Update Patient</button>
            </form>
        </div>
    );
}

export default UpdatePatientForm;
