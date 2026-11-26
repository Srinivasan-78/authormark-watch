const DEFAULT_MODEL = 'gemini-2.5-flash';

function buildPrompt({ repoName, stack, scorecard, todos }) {
  const failing = scorecard.filter(s => s.status !== 'Pass').map(s => `- ${s.category}: ${s.status} (${s.evidence})`).join('\n');
  const todoList = todos.slice(0, 12).map(t => `- [${t.priority}] ${t.id}: ${t.title} — ${t.reason}`).join('\n');
  return [
    `You are a Principal DevSecOps & Software Architect reviewing repository "${repoName}".`,
    `Detected stack: languages=[${(stack?.languages || []).join(', ')}], packageManager=${stack?.packageManager || 'none'}, hasTests=${Boolean(stack?.hasTests)}, linters=[${(stack?.linters || []).join(', ')}].`,
    failing ? `Scorecard gaps:\n${failing}` : 'All scorecard categories currently Pass.',
    todoList ? `Top TODOs:\n${todoList}` : '',
    'Provide 3-5 concise, actionable, repo-specific engineering recommendations (architecture, testing edge cases, or security hardening) in GitHub-flavored Markdown bullet points. Do not repeat generic boilerplate.',
  ].filter(Boolean).join('\n\n');
}

async function analyzeWithGemini(context, {
  apiKey = process.env.GEMINI_API_KEY,
  model = process.env.GEMINI_MODEL || DEFAULT_MODEL,
  fetchImpl = fetch,
  timeoutMs = 20000,
} = {}) {
  if (!apiKey) return { status: 'skipped', insights: null };

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;

  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: ctrl.signal,
      body: JSON.stringify({
        contents: [{ role: 'user', parts: [{ text: buildPrompt(context) }] }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 512 },
      }),
    });
    if (!res.ok) return { status: 'error', insights: null, error: `Gemini API HTTP ${res.status}` };
    const data = await res.json();
    const text = data?.candidates?.[0]?.content?.parts?.map(p => p.text).filter(Boolean).join('\n').trim() || null;
    return text ? { status: 'ok', insights: text } : { status: 'error', insights: null, error: 'Empty Gemini response' };
  } catch (err) {
    return { status: 'error', insights: null, error: err.message };
  } finally {
    clearTimeout(timer);
  }
}

export { DEFAULT_MODEL, buildPrompt, analyzeWithGemini };
