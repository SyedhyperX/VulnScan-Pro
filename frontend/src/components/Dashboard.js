import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import ScanForm from './ScanForm';
import ResultsTable from './ResultsTable';
import axios from 'axios';

const Dashboard = () => {
  const { user, logout } = useAuth();
  const [stats, setStats] = useState({
    total_scans: 0,
    recent_scans: []
  });
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchDashboardData();
    fetchScans();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const response = await axios.get('/api/dashboard/stats');
      setStats(response.data);
    } catch (err) {
      setError('Failed to load dashboard data');
      console.error('Dashboard error:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchScans = async () => {
    try {
      const response = await axios.get('/api/scans');
      setScans(response.data.scans);
    } catch (err) {
      setError('Failed to load scans');
      console.error('Scans error:', err);
    }
  };

  const handleNewScan = (newScan) => {
    setScans([newScan, ...scans]);
    fetchDashboardData(); // Refresh stats
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
        <p>Loading dashboard...</p>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <div className="container">
          <nav className="dashboard-nav">
            <h1>🔍 VulnScan Pro</h1>
            <div className="user-info">
              <span className="user-name">Welcome, {user.username}</span>
              <button onClick={logout} className="btn btn-secondary">
                Logout
              </button>
            </div>
          </nav>
        </div>
      </header>

      <main className="container">
        {error && <div className="alert alert-error">{error}</div>}
        
        {/* Statistics */}
        <div className="stats-grid">
          <div className="stat-card">
            <h3>Total Scans</h3>
            <div className="stat-number">{stats.total_scans}</div>
            <div className="stat-label">All time</div>
          </div>
          <div className="stat-card">
            <h3>Recent Activity</h3>
            <div className="stat-number">{stats.recent_scans.length}</div>
            <div className="stat-label">Last 5 scans</div>
          </div>
          <div className="stat-card">
            <h3>Critical Issues</h3>
            <div className="stat-number">
              {stats.recent_scans.reduce((sum, scan) => sum + (scan.critical_count || 0), 0)}
            </div>
            <div className="stat-label">Needs attention</div>
          </div>
          <div className="stat-card">
            <h3>High Risk</h3>
            <div className="stat-number">
              {stats.recent_scans.reduce((sum, scan) => sum + (scan.high_count || 0), 0)}
            </div>
            <div className="stat-label">Recent scans</div>
          </div>
        </div>

        {/* New Scan Form */}
        <ScanForm onScanStart={handleNewScan} />

        {/* Recent Scans */}
        <ResultsTable scans={scans} onRefresh={fetchScans} />
      </main>
    </div>
  );
};

export default Dashboard;
