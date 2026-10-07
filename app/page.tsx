"use client";

import { useState } from 'react';

type Severity = 'low' | 'medium' | 'high';

type DetectionEntity = {
  label: string;
  category: string;
  value: string;
  replacement: string;
  severity: Severity;
  confidence: number;
  start: number;
  end: number;
};

type DetectionSummary = {
  total_entities: number;
  categories: Record<string, number>;
  risk_level: string;
};

type AnalysisResponse = {
  id: string;
  original_text: string;
  redacted_text: string;
  mode: 'mask' | 'redact';
  summary: DetectionSummary;
  entities: DetectionEntity[];
};

const DEFAULT_INPUT =
  'Contact John Doe at john.doe@example.com or +1 (555) 123-4567. My SSN is 123-45-6789 and my password is P@ssw0rd123!';

export default function Home() {
  const [text, setText] = useState(DEFAULT_INPUT);
  const [mode, setMode] = useState<'mask' | 'redact'>('mask');
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const submitAnalysis = async () => {
    const trimmed = text.trim();
    if (!trimmed) {
      setError('Please provide text to scan.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';
      const response = await fetch(`${apiBase}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: trimmed, mode })
      });

      if (!response.ok) {
        const payload = await response.json().catch(() => ({ detail: 'Unable to analyze text.' }));
        throw new Error(payload.detail || 'Unable to analyze text.');
      }

      const payload: AnalysisResponse = await response.json();
      setResult(payload);
    } catch (caughtError) {
      const message = caughtError instanceof Error ? caughtError.message : 'Unexpected error occurred.';
      setError(message);
      setResult(null);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main>
      <div className="page-shell">
        <section className="hero">
          <h1>PrivacyGuard AI</h1>
          <p>
            Paste unstructured text to identify likely sensitive data, review risk levels, and generate a safer redacted version.
            Detection is heuristic and should be reviewed by a human before final action.
          </p>
        </section>

        <section className="analysis-card">
          <div className="analysis-grid">
            <div>
              <label htmlFor="text-input">Content to analyze</label>
              <textarea
                id="text-input"
                value={text}
                onChange={(event) => setText(event.target.value)}
                placeholder="Paste text that may contain names, emails, phone numbers, addresses, IDs, or credentials..."
              />
              <div className="controls">
                <select id="mode-select" value={mode} onChange={(event) => setMode(event.target.value as 'mask' | 'redact')}>
                  <option value="mask">Mask</option>
                  <option value="redact">Redact</option>
                </select>
                <button type="button" onClick={submitAnalysis} disabled={loading}>
                  {loading ? 'Analyzing…' : 'Analyze text'}
                </button>
              </div>
              {error ? <div className="message error">{error}</div> : null}
            </div>

            <aside>
              <h3>Detection summary</h3>
              {result ? (
                <div className="summary-grid">
                  <div className="metric">
                    <small>Total entities</small>
                    <strong>{result.summary.total_entities}</strong>
                  </div>
                  <div className="metric">
                    <small>Risk</small>
                    <strong>{result.summary.risk_level}</strong>
                  </div>
                </div>
              ) : (
                <p className="message">No results yet. Submit content to inspect likely sensitive patterns.</p>
              )}
            </aside>
          </div>
        </section>

        {result ? (
          <section className="results-card">
            <div className="analysis-grid">
              <div>
                <h3>Original text</h3>
                <div className="original-box">{result.original_text}</div>
              </div>
              <div>
                <h3>Protected output</h3>
                <div className="redacted-box">{result.redacted_text}</div>
              </div>
            </div>

            <div className="summary-grid" style={{ marginTop: '18px' }}>
              {Object.entries(result.summary.categories).map(([category, value]) => (
                <div className="metric" key={category}>
                  <small>{category}</small>
                  <strong>{value}</strong>
                </div>
              ))}
            </div>

            <div style={{ marginTop: '22px' }}>
              <h3>Detected entities</h3>
              <ul className="entity-list">
                {result.entities.map((entity) => (
                  <li className="entity-item" key={`${entity.category}-${entity.start}-${entity.end}`}>
                    <header>
                      <span>{entity.label}</span>
                      <span className={`badge ${entity.severity}`}>{entity.severity}</span>
                    </header>
                    <div>
                      <strong>{entity.category}</strong>
                    </div>
                    <div>Value: {entity.value}</div>
                    <div>Replacement: {entity.replacement}</div>
                    <div>Confidence: {Math.round(entity.confidence * 100)}%</div>
                  </li>
                ))}
              </ul>
            </div>
          </section>
        ) : null}
      </div>
    </main>
  );
}
