import React, { useState } from 'react';
import axios from 'axios';

const ResultsTable = ({ scans, onRefresh }) => {
  const [scanDetails, setScanDetails] = useState({});
  const [loadingDetails, setLoadingDetails] = useState({});

  const fetchScanDetails = async (scanId) => {
    if (loadingDetails[scanId]) return;
    
    setLoadingDetails(prev => ({ ...prev, [scanId]: true }));
    
    try {
      const response = await axios.get(`/api/scan/${scanId}`);
      setScanDetails(prev => ({
        ...prev,
        [scanId]: response.data
      }));
    } catch (err) {
      console.error(`Failed to fetch details for scan ${scanId}:`, err);
    } finally {
      setLoadingDetails(prev => ({ ...prev, [scanId]: false }));
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const getStatusBadge = (status) => {
    const statusClass = `status-badge status-${status}`;
    return <span className={statusClass}>{status}</span>;
  };

  const getSeverityBadge = (severity, count) => {
    if (!count || count === 0) return null;
    const severityClass = `status-badge severity-${severity.toLowerCase()}`;
    return <span className={severityClass}>{count} {severity}</span>;
  };

  const handleViewDetails = (scanId) => {
    if (!scanDetails[scanId]) {
      fetchScanDetails(scanId);
    }
  };

  return (
    <div className="results-table">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Scan Results</h3>
        <button onClick={onRefresh} className="btn btn-secondary">
          Refresh
        </button>
      </div>
      
      {scans.length === 0 ? (
        <div style={{ padding: '40px', textAlign: 'center', color: '#6c757d' }}>
          No scans yet. Start your first security scan above!
        </div>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Type</th>
              <th>Status</th>
              <th>Vulnerabilities</th>
              <th>Started</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <React.Fragment key={scan.id}>
                <tr>
                  <td>{scan.target}</td>
                  <td>{scan.scan_type}</td>
                  <td>{getStatusBadge(scan.status)}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      {getSeverityBadge('Critical', scan.critical_count)}
                      {getSeverityBadge('High', scan.high_count)}
                      {getSeverityBadge('Medium', scan.medium_count)}
                      {getSeverityBadge('Low', scan.low_count)}
                      {!scan.vulnerabilities_found && scan.status === 'completed' && (
                        <span style={{ color: '#28a745', fontWeight: 'bold' }}>✓ Clean</span>
                      )}
                    </div>
                  </td>
                  <td>{formatDate(scan.created_at)}</td>
                  <td>
                    <button
                      onClick={() => handleViewDetails(scan.id)}
                      className="btn btn-secondary"
                      style={{ fontSize: '12px', padding: '4px 8px' }}
                    >
                      {loadingDetails[scan.id] ? 'Loading...' : 'View Details'}
                    </button>
                  </td>
                </tr>
                {scanDetails[scan.id] && (
                  <tr>
                    <td colSpan="6">
                      <ScanDetails details={scanDetails[scan.id]} />
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

const ScanDetails = ({ details }) => {
  if (details.status === 'running') {
    return (
      <div className="scan-progress">
        <div className="progress-bar">
          <div 
            className="progress-fill" 
            style={{ width: `${details.progress || 0}%` }}
          ></div>
        </div>
        <div className="progress-text">
          {details.current_task || 'Processing...'} ({details.progress || 0}%)
        </div>
      </div>
    );
  }

  if (details.status === 'failed') {
    return (
      <div className="alert alert-error">
        <strong>Scan Failed:</strong> {details.current_task || 'Unknown error occurred'}
      </div>
    );
  }

  if (!details.vulnerabilities || details.vulnerabilities.length === 0) {
    return (
      <div className="alert alert-success">
        <strong>Great!</strong> No vulnerabilities were found in this scan.
      </div>
    );
  }

  return (
    <div style={{ padding: '20px', background: '#f8f9fa' }}>
      <h4>Vulnerabilities Found ({details.vulnerabilities.length})</h4>
      <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
        {details.vulnerabilities.map((vuln, index) => (
          <div 
            key={index}
            style={{
              background: 'white',
              padding: '15px',
              marginBottom: '10px',
              borderRadius: '8px',
              border: '1px solid #dee2e6'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <strong>{vuln.title}</strong>
              <span className={`status-badge severity-${vuln.severity.toLowerCase()}`}>
                {vuln.severity}
              </span>
            </div>
            <div style={{ color: '#6c757d', fontSize: '14px', marginBottom: '8px' }}>
              <strong>Type:</strong> {vuln.type}
            </div>
            <div style={{ color: '#495057', marginBottom: '8px' }}>
              {vuln.description}
            </div>
            {vuln.url && (
              <div style={{ color: '#6c757d', fontSize: '12px' }}>
                <strong>URL:</strong> {vuln.url}
              </div>
            )}
            {vuln.payload && (
              <div style={{ color: '#6c757d', fontSize: '12px', marginTop: '4px' }}>
                <strong>Payload:</strong> <code>{vuln.payload}</code>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default ResultsTable;

