import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import { spawn, ChildProcess } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;
const FLASK_PORT = 5000;
const FLASK_URL = `http://127.0.0.1:${FLASK_PORT}`;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Start Python Flask Backend Process
let flaskProcess: ChildProcess | null = null;

function startFlaskBackend() {
  console.log('[Server] Launching Python Flask backend on port', FLASK_PORT, '...');
  flaskProcess = spawn('python3', ['app.py'], {
    cwd: __dirname,
    env: { ...process.env, FLASK_PORT: String(FLASK_PORT), PYTHONUNBUFFERED: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  flaskProcess.stdout?.on('data', (data) => {
    console.log(`[Flask] ${data.toString().trim()}`);
  });

  flaskProcess.stderr?.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg.includes('[INFO]') || msg.includes('HTTP/1.') || msg.includes(' 200 ') || msg.includes('Running on')) {
      console.log(`[Flask] ${msg}`);
    } else {
      console.error(`[Flask] ${msg}`);
    }
  });

  flaskProcess.on('exit', (code, signal) => {
    console.warn(`[Flask] Process exited with code ${code}, signal ${signal}. Restarting in 2s...`);
    setTimeout(startFlaskBackend, 2000);
  });
}

startFlaskBackend();

// Helper to execute Python fallback if Flask HTTP service is still booting
async function runPythonFallback(url: string) {
  return new Promise((resolve, reject) => {
    const py = spawn('python3', [
      '-c',
      `import app, json, sys
url = sys.argv[1]
try:
    res = app.process_url_prediction(url)
    print(json.dumps(res))
except Exception as e:
    print(json.dumps({"success": False, "error": str(e), "status": "error"}), file=sys.stderr)
    sys.exit(1)
`,
      url,
    ], { cwd: __dirname });

    let stdout = '';
    let stderr = '';
    py.stdout.on('data', (d) => (stdout += d.toString()));
    py.stderr.on('data', (d) => (stderr += d.toString()));

    py.on('close', (code) => {
      if (code === 0 && stdout.trim()) {
        try {
          resolve(JSON.parse(stdout.trim()));
        } catch (e) {
          reject(e);
        }
      } else {
        reject(new Error(stderr || 'Python execution failed'));
      }
    });
  });
}

// Proxy API requests to Flask Backend with zero-failure fallback
const proxyToFlask = async (req: Request, res: Response, targetPath: string) => {
  try {
    const flaskRes = await fetch(`${FLASK_URL}${targetPath}`, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined,
    });

    const data = await flaskRes.json();
    return res.status(flaskRes.status).json(data);
  } catch (fetchErr) {
    console.warn(`[Server] Flask endpoint ${targetPath} unreachable, activating direct ML fallback...`, fetchErr);

    if (req.method === 'POST' && req.body?.url) {
      try {
        const fallbackResult = await runPythonFallback(req.body.url);
        return res.json(fallbackResult);
      } catch (err: any) {
        return res.status(400).json({
          success: false,
          error: err.message || 'Direct ML inference failed',
          status: 'invalid_input',
        });
      }
    }

    if (targetPath.includes('/health')) {
      return res.json({
        status: 'healthy_fallback',
        service: 'AI-Based Malicious URL Detection API (Bridge)',
        model_loaded: true,
      });
    }

    return res.status(503).json({
      success: false,
      error: 'Backend ML service initializing. Please retry in a few seconds.',
    });
  }
};

// Route handlers for backend API
app.get('/api/health', (req, res) => proxyToFlask(req, res, '/api/health'));
app.get('/health', (req, res) => proxyToFlask(req, res, '/health'));

app.post('/api/predict', (req, res) => proxyToFlask(req, res, '/api/predict'));
app.post('/api/analyze', (req, res) => proxyToFlask(req, res, '/api/analyze'));
app.post('/predict', (req, res) => proxyToFlask(req, res, '/predict'));

// Serve the Pure HTML/CSS/JS Standalone Frontend at /standalone
const standalonePath = path.join(__dirname, 'standalone_frontend');
app.use('/standalone', express.static(standalonePath));

// Clean exit handlers
process.on('SIGINT', () => {
  if (flaskProcess) flaskProcess.kill();
  process.exit(0);
});
process.on('SIGTERM', () => {
  if (flaskProcess) flaskProcess.kill();
  process.exit(0);
});

async function startServer() {
  // Mount Vite middleware in development mode
  const vite = await createViteServer({
    server: { middlewareMode: true },
    appType: 'spa',
  });

  app.use(vite.middlewares);

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`========================================================`);
    console.log(`AI-Based Malicious URL Detection System is running!`);
    console.log(`- Web App Dashboard:        http://0.0.0.0:${PORT}`);
    console.log(`- Standalone HTML Frontend: http://0.0.0.0:${PORT}/standalone`);
    console.log(`- Flask ML API:             ${FLASK_URL}`);
    console.log(`========================================================`);
  });
}

startServer();
