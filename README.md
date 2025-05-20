# Om Ambulance Project

This repository contains a full-stack web application for ambulance patient management with:

- **Backend:** Python (FastAPI)  
- **Frontend:** React (Vite + React Bootstrap)

## Project Structure

om_ambulance/
├── backend/ # Python FastAPI backend code
├── frontend/ # React frontend code
├── .gitignore # Git ignore rules
├── README.md # This file
└── venv/ # Python virtual environment (not committed)

## Download and Setup

### Clone the repository

git clone https://github.com/ajaybhandwalkar/om_ambulance.git
cd om_ambulance


### Backend Setup

cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
cd app
uvicorn main:app --reload


### Frontend Setup

cd ../frontend
npm install
npm run dev
