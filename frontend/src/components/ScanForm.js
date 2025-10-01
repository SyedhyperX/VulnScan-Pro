import React, { useState } from 'react';
import axios from 'axios';

const ScanForm = ({ onScanStart }) => {
  const [formData, setFormData] = useState({
    target: '',
    scan_type: 'comprehensive'
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const response = await axios.post('/api/scan', formData);
      setSuccess(`Scan started successfully! Scan ID: ${response.data.scan_id}`);
      onScanStart(response.data);
      setFormData({ target: '', scan_type: 'comprehensive' });
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="scan-form">
      <h3>Start New Security Scan</h3>
      
      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <form onSubmit={handleSubmit}>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="target">Target URL or IP</label>
            <input
              type="text"
              id="target"
              name="target"
              value={formData.target}
              onChange={handleChange}
              placeholder="https://example.com or 192.168.1.1"
              required
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="scan_type">Scan Type</label>
            <select
              id="scan_type"
              name="scan_type"
              value={formData.scan_type}
              onChange={handleChange}
            >
              <option value="comprehensive">Comprehensive</option>
              <option value="web">Web Vulnerabilities Only</option>
              <option value="port">Port Scan Only</option>
            </select>
          </div>
          
          <button 
            type="submit" 
            className="btn btn-primary"
            disabled={loading}
          >
            {loading ? 'Starting...' : 'Start Scan'}
          </button>
        </div>
      </form>
    </div>
  );
};

export default ScanForm;
