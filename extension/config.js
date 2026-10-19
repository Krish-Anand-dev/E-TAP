// E-TAP Local: the launcher serves the API on 127.0.0.1:5000 and the
// dashboard on 127.0.0.1:5173. For the hosted demo use
// https://etap-backend-od1c.onrender.com and https://e-tap-lac.vercel.app.
const ETAP_CONFIG = Object.freeze({
    version: '1.5.1',
    apiBaseUrl: 'http://127.0.0.1:5000',
    appBaseUrl: 'http://127.0.0.1:5173',
    requestTimeoutMs: 90000,
});
