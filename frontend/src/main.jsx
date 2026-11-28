import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { startTheme } from './utils/theme';
import './styles/index.css';
import './styles/upload.css';
import './styles/dashboard.css';
import './styles/report.css';

startTheme(); // day or night, before the first paint

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

import './styles/workspace.css';
import './styles/v2.css';
import './styles/welcome.css';
import './styles/sea.css';
import './styles/dark.css';
import './styles/night.css';
