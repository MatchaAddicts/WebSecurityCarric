const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const { getDb } = require('../db/schema');
const { verifyToken } = require('../middleware/auth');
const xml2js = require('xml2js');
const { solveChallenge } = require('../utils/challengeSolver');

const UPLOAD_DIR = path.join(__dirname, '..', '..', 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// POST /api/files/upload
// VULNERABILITY: Unrestricted file upload - only checks extension superficially
router.post('/upload', verifyToken, express.raw({ type: '*/*', limit: '10mb' }), (req, res) => {
  const filename = req.headers['x-filename'] || 'upload.txt';
  const db = getDb();

  const ext = path.extname(filename).toLowerCase();
  const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.xml'];

  // VULNERABILITY: Null byte can bypass extension check
  const cleanFilename = filename.split('\0')[0];
  const checkExt = path.extname(cleanFilename).toLowerCase();

  if (!allowedExts.includes(checkExt) && !allowedExts.includes(ext)) {
    const savedName = `${Date.now()}-${filename.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
    const filePath = path.join(UPLOAD_DIR, savedName);
    fs.writeFileSync(filePath, req.body || '');

    solveChallenge(req, 'file_upload');

    return res.status(400).json({
      error: 'File type not allowed',
      hint: 'Only jpg, png, gif, pdf, txt, xml files are allowed',
      but_saved_anyway: savedName
    });
  }

  try {
    const savedName = `${Date.now()}-${filename.replace(/\0/g, '').replace(/[^a-zA-Z0-9.-]/g, '_')}`;
    const filePath = path.join(UPLOAD_DIR, savedName);
    fs.writeFileSync(filePath, req.body || '');

    db.prepare('INSERT INTO user_files (user_id, filename, original_name) VALUES (?, ?, ?)').run(
      req.user.id, savedName, filename
    );

    const response = {
      message: 'File uploaded successfully',
      filename: savedName,
      original_name: filename
    };

    if (filename.includes('\0') || filename.includes('%00')) {
      solveChallenge(req, 'null_byte');
    }

    res.json(response);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/files/download?file=
// VULNERABILITY: Path Traversal
router.get('/download', (req, res) => {
  const { file } = req.query;

  if (!file) {
    return res.status(400).json({ error: 'File parameter is required' });
  }

  const filePath = path.join(UPLOAD_DIR, file);

  try {
    if (fs.existsSync(filePath)) {
      if (file.includes('..')) {
        solveChallenge(req, 'directory_listing');
        const content = fs.readFileSync(filePath, 'utf8');
        return res.json({
          content: content.substring(0, 1000),
          message: 'Path traversal detected!'
        });
      }
      res.sendFile(filePath);
    } else {
      res.status(404).json({ error: 'File not found', path_hint: filePath });
    }
  } catch (err) {
    res.status(500).json({ error: err.message, path: filePath });
  }
});

// POST /api/files/import-xml
// VULNERABILITY: XXE (XML External Entity)
router.post('/import-xml', verifyToken, express.text({ type: '*/xml', limit: '5mb' }), (req, res) => {
  const xmlData = req.body || req.query.xml;

  if (!xmlData) {
    return res.status(400).json({ error: 'XML data is required' });
  }

  const parser = new xml2js.Parser({
    explicitArray: false,
  });

  parser.parseString(xmlData, (err, result) => {
    if (err) {
      return res.status(400).json({ error: 'Invalid XML', details: err.message });
    }

    const response = {
      parsed: result,
      message: 'XML imported successfully'
    };

    if (xmlData.includes('<!ENTITY') || xmlData.includes('SYSTEM') || xmlData.includes('file://')) {
      solveChallenge(req, 'xxe_upload');
    }

    res.json(response);
  });
});

module.exports = router;
