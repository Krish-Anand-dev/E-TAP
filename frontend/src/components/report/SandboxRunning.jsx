import React from 'react';
import Icon from '../common/Icon';
import { sandboxPlace, sandboxProgress } from '../../utils/sandbox';

/** The big "Running" box: shows which step of the VM run is happening right now. */
export default function SandboxRunning({ sandbox }) {
  const { waiting, steps } = sandboxProgress(sandbox?.status);
  const current = steps.find((step) => step.state === 'active');
  return (
    <div className="sb-running" role="status" aria-live="polite">
      <div className="sb-running-head">
        <span className="sb-running-dot" aria-hidden="true" />
        <strong>{waiting ? 'Waiting' : 'Running'}</strong>
        <span>
          {waiting
            ? `Waiting for ${sandboxPlace(sandbox)} to pick this up.${sandbox?.mode === 'agent' ? ' Keep the E-TAP Sandbox Agent running.' : ''}`
            : `${current?.title || 'Working'} in ${sandboxPlace(sandbox)}`}
        </span>
      </div>
      <ol className="sb-steps">
        {steps.map((step, i) => (
          <li key={step.key} className={`sb-step ${step.state}`}>
            <span className="sb-step-mark" aria-hidden="true">
              {step.state === 'done' ? <Icon name="check" size={16} /> : i + 1}
            </span>
            <div>
              <b>{step.title}{step.state === 'active' && <span className="sb-dots" aria-hidden="true"><i>.</i><i>.</i><i>.</i></span>}</b>
              <span>{step.detail}</span>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
