import { log, warn, sanitize } from './github.mjs';
import { analyzeWithGemini } from './ai.mjs';

const PASSING_CONCLUSIONS = new Set(['success', 'neutral', 'skipped']);

async function evaluateDependabotPr(client, owner, repo, pr) {
  const details = await client.getPullRequest(owner, repo, pr.number);
  const sha = details?.head?.sha || pr.head?.sha;
  const mergeableState = details?.mergeable_state || 'unknown';

  const checkData = sha ? await client.getCommitCheckRuns(owner, repo, sha).catch(() => ({ check_runs: [] })) : { check_runs: [] };
  const runs = Array.isArray(checkData?.check_runs) ? checkData.check_runs : [];

  const pending = runs.filter(r => r.status !== 'completed');
  const failed = runs.filter(r => r.status === 'completed' && !PASSING_CONCLUSIONS.has(r.conclusion));

  if (failed.length > 0) {
    return {
      action: 'failed',
      reason: `${failed.length} CI check(s) failed: ${failed.map(f => f.name).join(', ')}`,
      failedChecks: failed.map(f => ({ name: f.name, conclusion: f.conclusion, url: f.html_url })),
      mergeableState,
    };
  }

  if (mergeableState === 'dirty' || mergeableState === 'behind') {
    return {
      action: 'rebase',
      reason: `PR mergeable_state is "${mergeableState}"`,
      failedChecks: [],
      mergeableState,
    };
  }

  if (pending.length > 0) {
    return {
      action: 'pending',
      reason: `${pending.length} CI check(s) still running`,
      failedChecks: [],
      mergeableState,
    };
  }

  if (mergeableState === 'clean' || mergeableState === 'has_hooks' || (runs.length > 0 && details?.mergeable !== false)) {
    return {
      action: 'merge',
      reason: runs.length > 0 ? `All ${runs.length} CI check(s) passed` : 'No blocking checks and mergeable',
      failedChecks: [],
      mergeableState,
    };
  }

  return {
    action: 'blocked',
    reason: `PR not ready (mergeable_state=${mergeableState})`,
    failedChecks: [],
    mergeableState,
  };
}

async function processDependabotPrs({
  owner,
  repos,
  client,
  dryRun = false,
  useAi = false,
  mergeMethod = 'squash',
} = {}) {
  const results = [];
  if (!client?.token) return results;

  for (const repoInfo of repos) {
    const repo = repoInfo.name;
    let prs = [];
    try {
      prs = (await client.listOpenPullRequests(owner, repo)) || [];
    } catch (err) {
      warn(`Could not list PRs for ${repo}: ${sanitize(err.message)}`);
      continue;
    }

    const depPrs = prs.filter(p => p.user?.login === 'dependabot[bot]');
    for (const pr of depPrs) {
      const evalRes = await evaluateDependabotPr(client, owner, repo, pr);
      const entry = {
        repo,
        number: pr.number,
        title: pr.title,
        url: pr.html_url,
        status: evalRes.action,
        reason: evalRes.reason,
        failedChecks: evalRes.failedChecks,
        aiDiagnosis: null,
      };

      if (evalRes.action === 'failed' && useAi) {
        const ai = await analyzeWithGemini({
          repoName: `${repo}#${pr.number}`,
          stack: { languages: [repoInfo.language || 'unknown'], linters: [] },
          scorecard: [],
          todos: evalRes.failedChecks.map(c => ({
            priority: 'High',
            id: 'CI-FAIL',
            title: `Dependabot PR "${pr.title}" failed check ${c.name}`,
            reason: `Conclusion: ${c.conclusion}`,
          })),
        });
        if (ai.status === 'ok') entry.aiDiagnosis = ai.insights;
      }

      if (!dryRun) {
        try {
          if (evalRes.action === 'merge') {
            await client.mergePullRequest(owner, repo, pr.number, { mergeMethod });
            entry.status = 'merged';
            log(`Merged Dependabot PR ${repo}#${pr.number}: ${pr.title}`);
          } else if (evalRes.action === 'rebase') {
            await client.addComment(owner, repo, pr.number, '@dependabot rebase');
            entry.status = 'rebased';
            log(`Requested @dependabot rebase on ${repo}#${pr.number}`);
          }
        } catch (err) {
          entry.status = 'error';
          entry.reason = sanitize(err.message);
        }
      }

      results.push(entry);
    }
  }

  return results;
}

export { evaluateDependabotPr, processDependabotPrs };
