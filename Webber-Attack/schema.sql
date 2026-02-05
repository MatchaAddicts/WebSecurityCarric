-- Create database (if not exists)
CREATE DATABASE IF NOT EXISTS webber_attack;
USE webber_attack;

-- =====================
-- Core tables
-- =====================

-- Scans table
CREATE TABLE scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target VARCHAR(500) NOT NULL,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME NULL,
    status ENUM('running', 'paused', 'completed', 'failed') DEFAULT 'running',
    flags JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    owasp_category ENUM('A01','A02','A03','A04','A05','A06','A07','A08','A09','A10') NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity ENUM('critical', 'high', 'medium', 'low', 'info') NOT NULL,
    cvss_score DECIMAL(3,1) NULL,
    cve_id VARCHAR(20) NULL,
    endpoint VARCHAR(500),
    evidence TEXT,
    exploited BOOLEAN DEFAULT FALSE,
    exploit_evidence TEXT,
    confidence INT DEFAULT 0,
    found_by JSON,
    mitre_attack_id VARCHAR(20) NULL,
    mitre_technique VARCHAR(255) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Generated code (PoC exploits)
CREATE TABLE generated_code (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    vuln_id INT NOT NULL,
    type ENUM('poc', 'exploit', 'payload', 'wordlist', 'script') NOT NULL,
    code LONGTEXT NOT NULL,
    language VARCHAR(50),
    success_rate DECIMAL(5,2) DEFAULT 0.00,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

-- Patches table
CREATE TABLE patches (
    id INT AUTO_INCREMENT PRIMARY KEY,
    vuln_id INT NOT NULL,
    patch_code LONGTEXT NOT NULL,
    patch_type ENUM('code_fix', 'config', 'middleware', 'dependency_update') NOT NULL,
    file_path VARCHAR(500),
    validation_status ENUM('pending', 'validated', 'failed') DEFAULT 'pending',
    docker_validated BOOLEAN DEFAULT FALSE,
    validation_log TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

-- =====================
-- Learning tables
-- =====================

-- Learned techniques
CREATE TABLE learned_techniques (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pattern VARCHAR(255) NOT NULL,
    context TEXT,
    technique_type ENUM('recon', 'exploit', 'bypass', 'patch') NOT NULL,
    success_rate DECIMAL(5,2) DEFAULT 0.00,
    usage_count INT DEFAULT 0,
    last_used DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_pattern (pattern)
);

-- Tool usage stats
CREATE TABLE tool_usage (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tool_name VARCHAR(100) NOT NULL,
    category ENUM('recon', 'exploit', 'util', 'patch') NOT NULL,
    usage_count INT DEFAULT 0,
    avg_effectiveness DECIMAL(5,2) DEFAULT 0.00,
    last_used DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_tool (tool_name)
);

-- =====================
-- State & logging
-- =====================

-- Scan state (for --resume)
CREATE TABLE scan_state (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    phase ENUM('recon', 'exploit', 'patch', 'validate', 'report') NOT NULL,
    progress INT DEFAULT 0,
    checkpoint_data JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Action log (audit trail)
CREATE TABLE action_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    agent ENUM('claude_brain', 'claude_scanner', 'gpt_scanner', 'gemini_scanner', 'deepseek_scanner') NOT NULL,
    action_type ENUM('decision', 'tool_call', 'finding', 'patch', 'validation', 'error') NOT NULL,
    reasoning TEXT,
    tool_used VARCHAR(100),
    command_executed TEXT,
    result_summary TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Scope config
CREATE TABLE scope_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    domain VARCHAR(255) NOT NULL,
    include BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- =====================
-- Deployment tables
-- =====================

-- Ansible playbooks
CREATE TABLE playbooks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    playbook_yaml LONGTEXT NOT NULL,
    status ENUM('generated', 'approved', 'deployed', 'failed') DEFAULT 'generated',
    deployed_at DATETIME NULL,
    deployment_log TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- GitHub integration
CREATE TABLE github_repos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    repo_url VARCHAR(500) NOT NULL,
    branch VARCHAR(100) DEFAULT 'main',
    clone_path VARCHAR(500),
    pr_created BOOLEAN DEFAULT FALSE,
    pr_url VARCHAR(500),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- =====================
-- Indexes for performance
-- =====================

CREATE INDEX idx_vuln_scan ON vulnerabilities(scan_id);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_owasp ON vulnerabilities(owasp_category);
CREATE INDEX idx_patches_vuln ON patches(vuln_id);
CREATE INDEX idx_action_scan ON action_log(scan_id);
CREATE INDEX idx_action_time ON action_log(timestamp);
