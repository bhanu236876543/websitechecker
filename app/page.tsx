"use client";

import { FormEvent, useState } from "react";
import Report, { Analysis } from "./report";

const steps = ["Validating public URLs", "Checking HTTPS and response headers", "Inspecting cookies and public exposure", "Understanding the GitHub repository", "Calculating your security score", "Generating your report"];

export default function Home() {
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [githubUrl, setGithubUrl] = useState("");
  const [demo, setDemo] = useState(false);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const [error, setError] = useState("");
  const [report, setReport] = useState<Analysis | null>(null);

  async function analyze(event: FormEvent) {
    event.preventDefault(); setError(""); setReport(null); setLoading(true); setStep(0);
    const timer = window.setInterval(() => setStep(s => Math.min(s + 1, steps.length - 1)), 620);
    try {
      const res = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ websiteUrl, githubUrl, demo }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Analysis could not be completed.");
      setStep(steps.length - 1); setReport(data);
    } catch (e) { setError(e instanceof Error ? e.message : "Something went wrong."); }
    finally { window.clearInterval(timer); setLoading(false); }
  }

  return <main>
    <nav><a className="brand" href="#top"><i>✓</i> WebsiteChecker</a><span>Defensive project intelligence</span></nav>
    <section className="hero" id="top">
      <div className="eyebrow">AUTOMATED SECURITY ASSESSMENT</div>
      <h1>Is your project<br/><em>actually secure?</em></h1>
      <p>Give us a public website or GitHub repository. We’ll inspect it, explain what it does, and turn practical security signals into a clear report.</p>
      <form onSubmit={analyze} className="analyze-form">
        <label>Website URL <input value={websiteUrl} onChange={e => setWebsiteUrl(e.target.value)} placeholder="https://your-project.com" type="url" /></label>
        <div className="or">OR</div>
        <label>GitHub repository URL <input value={githubUrl} onChange={e => setGithubUrl(e.target.value)} placeholder="https://github.com/you/project" type="url" /></label>
        <label className="demo"><input type="checkbox" checked={demo} onChange={e => setDemo(e.target.checked)} /> Use demo data <small>Explore the full report without contacting a website.</small></label>
        <button disabled={loading}>{loading ? "Analyzing…" : "Analyze Project  →"}</button>
        {error && <p className="error">{error}</p>}
      </form>
      <p className="notice">Safe, non-destructive checks only. Automated assessments never guarantee complete security.</p>
    </section>
    {loading && <section className="progress"><div className="eyebrow">ANALYSIS IN PROGRESS</div><h2>Looking at your project</h2>{steps.map((item, i) => <div className={i <= step ? "progress-step active" : "progress-step"} key={item}><b>{i < step ? "✓" : i === step ? "•" : "○"}</b>{item}</div>)}</section>}
    {report && <Report analysis={report} />}
  </main>;
}
