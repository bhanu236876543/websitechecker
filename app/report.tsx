export type Finding = { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"; title: string; description: string; evidence: string; remediation: string; source: string; confidence: string };
export type Analysis = { demo: boolean; score: number; status: string; websiteUrl?: string; githubUrl?: string; project: { name: string; overview: string; stack: string[]; architecture: string[]; importantFiles: { path: string; purpose: string }[] }; checks: string[]; findings: Finding[]; generatedAt: string };

const classFor = (severity: Finding["severity"]) => `severity ${severity.toLowerCase()}`;
export default function Report({ analysis: a }: { analysis: Analysis }) {
  const grouped = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
  return <section className="report" id="report">
    {a.demo && <div className="demo-banner">DEMO DATA — these results are illustrative and were not collected from a live target.</div>}
    <header className="report-header"><div><div className="eyebrow">PROJECT SECURITY REPORT</div><h2>{a.project.name}</h2><p>{a.websiteUrl || a.githubUrl || "Demo project"}</p></div><div className="score"><strong>{a.score}</strong><span>/100</span><small>{a.status}</small></div></header>
    <div className="grid intro"><article><h3>Project overview</h3><p>{a.project.overview}</p><div className="chips">{a.project.stack.map(x => <span key={x}>{x}</span>)}</div></article><article><h3>What’s going well</h3>{a.checks.length ? a.checks.map(x => <p className="check" key={x}>✓ {x}</p>) : <p>No positive signals were established in this scan.</p>}</article></div>
    <article className="architecture"><h3>Project architecture</h3><div>{a.project.architecture.map((x, i) => <span key={x}>{x}{i < a.project.architecture.length - 1 && <b>→</b>}</span>)}</div></article>
    <section className="findings"><div><div className="eyebrow">ACTIONABLE RESULTS</div><h2>Security findings</h2></div>{a.findings.length === 0 && <article className="finding clean"><h3>No scanner findings</h3><p>No common issues were detected by these limited automated checks. Manual review is still important.</p></article>}{grouped.map(level => a.findings.filter(f => f.severity === level).map(f => <article className="finding" key={f.title}><div><span className={classFor(f.severity)}>{f.severity}</span><span className="source">{f.source}</span></div><h3>{f.title}</h3><p>{f.description}</p><dl><dt>Evidence</dt><dd>{f.evidence}</dd><dt>Recommended fix</dt><dd>{f.remediation}</dd></dl><small>Confidence: {f.confidence}</small></article>))}</section>
    {a.project.importantFiles.length > 0 && <section className="files"><h2>Important files</h2>{a.project.importantFiles.map(f => <article key={f.path}><code>{f.path}</code><span>{f.purpose}</span></article>)}</section>}
    <p className="disclaimer">Generated {new Date(a.generatedAt).toLocaleString()}. This is an automated, non-invasive assessment—not a security guarantee.</p>
  </section>;
}
