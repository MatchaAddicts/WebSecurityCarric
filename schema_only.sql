/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19-11.8.5-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: webber_attack
-- ------------------------------------------------------
-- Server version	11.8.5-MariaDB-4 from Debian

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;

--
-- Table structure for table `action_log`
--

DROP TABLE IF EXISTS `action_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `action_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) NOT NULL,
  `timestamp` datetime DEFAULT current_timestamp(),
  `agent` varchar(100) DEFAULT NULL,
  `action_type` varchar(50) NOT NULL DEFAULT 'exec',
  `reasoning` text DEFAULT NULL,
  `tool_used` varchar(100) DEFAULT NULL,
  `command_executed` text DEFAULT NULL,
  `result_summary` mediumtext DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_action_scan` (`scan_id`),
  KEY `idx_action_time` (`timestamp`),
  CONSTRAINT `action_log_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=16820 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `attack_chains`
--

DROP TABLE IF EXISTS `attack_chains`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `attack_chains` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) NOT NULL,
  `chain_id` varchar(50) NOT NULL,
  `chain_name` varchar(255) DEFAULT NULL,
  `total_depth` int(11) DEFAULT 1,
  `root_vuln_id` int(11) DEFAULT NULL,
  `completed` tinyint(1) DEFAULT 0,
  `created_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_scan` (`scan_id`),
  KEY `idx_chain_id` (`chain_id`),
  KEY `root_vuln_id` (`root_vuln_id`),
  CONSTRAINT `attack_chains_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `attack_chains_ibfk_2` FOREIGN KEY (`root_vuln_id`) REFERENCES `vulnerabilities` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `attack_state`
--

DROP TABLE IF EXISTS `attack_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `attack_state` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) NOT NULL,
  `state_type` enum('secret','auth','hash','credential','endpoint','other') NOT NULL,
  `key_name` varchar(100) NOT NULL,
  `value` text DEFAULT NULL,
  `source_vuln_id` int(11) DEFAULT NULL,
  `discovered_at` datetime DEFAULT current_timestamp(),
  `used_count` int(11) DEFAULT 0,
  `last_used` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_scan_key` (`scan_id`,`key_name`),
  KEY `idx_scan` (`scan_id`),
  KEY `idx_type` (`state_type`),
  KEY `idx_key` (`key_name`),
  KEY `source_vuln_id` (`source_vuln_id`),
  CONSTRAINT `attack_state_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `attack_state_ibfk_2` FOREIGN KEY (`source_vuln_id`) REFERENCES `vulnerabilities` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `generated_code`
--

DROP TABLE IF EXISTS `generated_code`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `generated_code` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) NOT NULL,
  `vuln_id` int(11) NOT NULL,
  `type` enum('poc','exploit','payload','wordlist','script') NOT NULL,
  `code` longtext NOT NULL,
  `language` varchar(50) DEFAULT NULL,
  `success_rate` decimal(5,2) DEFAULT 0.00,
  `created_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  KEY `vuln_id` (`vuln_id`),
  CONSTRAINT `generated_code_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE,
  CONSTRAINT `generated_code_ibfk_2` FOREIGN KEY (`vuln_id`) REFERENCES `vulnerabilities` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `github_repos`
--

DROP TABLE IF EXISTS `github_repos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `github_repos` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) NOT NULL,
  `repo_url` varchar(500) NOT NULL,
  `branch` varchar(100) DEFAULT 'main',
  `clone_path` varchar(500) DEFAULT NULL,
  `pr_created` tinyint(1) DEFAULT 0,
  `pr_url` varchar(500) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  CONSTRAINT `github_repos_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `learned_techniques`
--

DROP TABLE IF EXISTS `learned_techniques`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `learned_techniques` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `pattern` varchar(255) NOT NULL,
  `context` text DEFAULT NULL,
  `technique_type` enum('recon','exploit','bypass','patch') NOT NULL,
  `success_rate` decimal(5,2) DEFAULT 0.00,
  `usage_count` int(11) DEFAULT 0,
  `last_used` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_pattern` (`pattern`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `patches`
--

DROP TABLE IF EXISTS `patches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `patches` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vuln_id` int(11) NOT NULL,
  `patch_code` longtext NOT NULL,
  `patch_type` enum('code_fix','config','middleware','dependency_update') NOT NULL,
  `file_path` varchar(500) DEFAULT NULL,
  `validation_status` enum('pending','validated','failed') DEFAULT 'pending',
  `docker_validated` tinyint(1) DEFAULT 0,
  `validation_log` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_patches_vuln` (`vuln_id`),
  CONSTRAINT `patches_ibfk_1` FOREIGN KEY (`vuln_id`) REFERENCES `vulnerabilities` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `payload_results`
--

DROP TABLE IF EXISTS `payload_results`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `payload_results` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) NOT NULL,
  `vuln_type` varchar(50) NOT NULL,
  `payload` text NOT NULL,
  `endpoint` varchar(500) DEFAULT NULL,
  `success` tinyint(1) NOT NULL,
  `response_code` int(11) DEFAULT NULL,
  `response_time_ms` int(11) DEFAULT NULL,
  `tested_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_scan` (`scan_id`),
  KEY `idx_vuln_type` (`vuln_type`),
  KEY `idx_success` (`success`),
  CONSTRAINT `payload_results_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `playbooks`
--

DROP TABLE IF EXISTS `playbooks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `playbooks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) NOT NULL,
  `playbook_yaml` longtext NOT NULL,
  `status` enum('generated','approved','deployed','failed') DEFAULT 'generated',
  `deployed_at` datetime DEFAULT NULL,
  `deployment_log` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  CONSTRAINT `playbooks_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scan_state`
--

DROP TABLE IF EXISTS `scan_state`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `scan_state` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) NOT NULL,
  `phase` enum('recon','exploit','patch','validate','report') NOT NULL,
  `progress` int(11) DEFAULT 0,
  `checkpoint_data` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`checkpoint_data`)),
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  CONSTRAINT `scan_state_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scans`
--

DROP TABLE IF EXISTS `scans`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `scans` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `target` varchar(500) NOT NULL,
  `start_time` datetime DEFAULT current_timestamp(),
  `end_time` datetime DEFAULT NULL,
  `status` enum('running','paused','completed','failed') DEFAULT 'running',
  `flags` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`flags`)),
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=139 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `scope_config`
--

DROP TABLE IF EXISTS `scope_config`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `scope_config` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) NOT NULL,
  `domain` varchar(255) NOT NULL,
  `include` tinyint(1) DEFAULT 1,
  `created_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`),
  CONSTRAINT `scope_config_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tested_patterns`
--

DROP TABLE IF EXISTS `tested_patterns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `tested_patterns` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) NOT NULL,
  `pattern` varchar(500) NOT NULL,
  `pattern_type` enum('endpoint','parameter','payload') NOT NULL,
  `result` enum('exploitable','not_vulnerable','blocked','error') NOT NULL,
  `test_count` int(11) DEFAULT 1,
  `first_tested` datetime DEFAULT current_timestamp(),
  `last_tested` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `notes` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_scan_pattern` (`scan_id`,`pattern`,`pattern_type`),
  KEY `idx_scan` (`scan_id`),
  KEY `idx_pattern` (`pattern`),
  KEY `idx_result` (`result`),
  CONSTRAINT `tested_patterns_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tool_usage`
--

DROP TABLE IF EXISTS `tool_usage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `tool_usage` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tool_name` varchar(100) NOT NULL,
  `category` enum('recon','exploit','util','patch') NOT NULL,
  `usage_count` int(11) DEFAULT 0,
  `avg_effectiveness` decimal(5,2) DEFAULT 0.00,
  `last_used` datetime DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_tool` (`tool_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vulnerabilities`
--

DROP TABLE IF EXISTS `vulnerabilities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `vulnerabilities` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scan_id` int(11) NOT NULL,
  `owasp_category` enum('A01','A02','A03','A04','A05','A06','A07','A08','A09','A10') NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text DEFAULT NULL,
  `severity` enum('critical','high','medium','low','info') NOT NULL,
  `cvss_score` decimal(3,1) DEFAULT NULL,
  `cve_id` varchar(20) DEFAULT NULL,
  `endpoint` varchar(500) DEFAULT NULL,
  `evidence` text DEFAULT NULL,
  `exploited` tinyint(1) DEFAULT 0,
  `exploit_evidence` text DEFAULT NULL,
  `confidence` int(11) DEFAULT 0,
  `found_by` text DEFAULT NULL,
  `remediation` text DEFAULT NULL,
  `mitre_attack_id` varchar(20) DEFAULT NULL,
  `mitre_technique` varchar(255) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `validation_result` varchar(50) DEFAULT 'validated',
  `validation_confidence` float DEFAULT 1,
  `validation_evidence` text DEFAULT NULL,
  `validation_method` varchar(100) DEFAULT NULL,
  `attack_chain_id` varchar(50) DEFAULT NULL,
  `depth_level` int(11) DEFAULT 1,
  `parent_vuln_id` int(11) DEFAULT NULL,
  `requires_auth` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `idx_vuln_scan` (`scan_id`),
  KEY `idx_vuln_severity` (`severity`),
  KEY `idx_vuln_owasp` (`owasp_category`),
  KEY `idx_chain` (`attack_chain_id`),
  KEY `idx_depth` (`depth_level`),
  KEY `idx_parent` (`parent_vuln_id`),
  CONSTRAINT `vulnerabilities_ibfk_1` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1244 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;

-- Dump completed on 2026-02-04 22:22:46
