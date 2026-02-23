import { Command } from "commander";
import { readFileSync } from "node:fs";

/**
 * Simple unified diff of two text files, implemented in pure TypeScript.
 */
function unifiedDiff(
  oldText: string,
  newText: string,
  oldLabel: string,
  newLabel: string,
): string {
  const oldLines = oldText.split("\n");
  const newLines = newText.split("\n");

  const lines: string[] = [];
  lines.push(`--- ${oldLabel}`);
  lines.push(`+++ ${newLabel}`);

  // Simple line-by-line comparison using LCS
  const lcs = computeLCS(oldLines, newLines);
  let oi = 0, ni = 0, li = 0;

  // Collect hunks
  const hunks: { oldStart: number; oldLen: number; newStart: number; newLen: number; lines: string[] }[] = [];
  let currentHunk: { oldStart: number; oldLen: number; newStart: number; newLen: number; lines: string[] } | null = null;
  let contextBefore: string[] = [];

  while (oi < oldLines.length || ni < newLines.length) {
    if (li < lcs.length && oi < oldLines.length && ni < newLines.length && oldLines[oi] === lcs[li] && newLines[ni] === lcs[li]) {
      // Common line
      if (currentHunk) {
        currentHunk.lines.push(` ${oldLines[oi]}`);
        currentHunk.oldLen++;
        currentHunk.newLen++;
      } else {
        contextBefore.push(` ${oldLines[oi]}`);
        if (contextBefore.length > 3) contextBefore.shift();
      }
      oi++;
      ni++;
      li++;
    } else if (oi < oldLines.length && (li >= lcs.length || oldLines[oi] !== lcs[li])) {
      // Deleted line
      if (!currentHunk) {
        currentHunk = {
          oldStart: oi - contextBefore.length + 1,
          oldLen: contextBefore.length,
          newStart: ni - contextBefore.length + 1,
          newLen: contextBefore.length,
          lines: [...contextBefore],
        };
        contextBefore = [];
      }
      currentHunk.lines.push(`-${oldLines[oi]}`);
      currentHunk.oldLen++;
      oi++;
    } else if (ni < newLines.length && (li >= lcs.length || newLines[ni] !== lcs[li])) {
      // Added line
      if (!currentHunk) {
        currentHunk = {
          oldStart: oi - contextBefore.length + 1,
          oldLen: contextBefore.length,
          newStart: ni - contextBefore.length + 1,
          newLen: contextBefore.length,
          lines: [...contextBefore],
        };
        contextBefore = [];
      }
      currentHunk.lines.push(`+${newLines[ni]}`);
      currentHunk.newLen++;
      ni++;
    }

    // Check if hunk should be flushed (3 context lines after last change)
    if (currentHunk) {
      const lastThree = currentHunk.lines.slice(-3);
      if (lastThree.length === 3 && lastThree.every((l) => l.startsWith(" "))) {
        hunks.push(currentHunk);
        currentHunk = null;
        contextBefore = lastThree.map((l) => l);
      }
    }
  }

  if (currentHunk) hunks.push(currentHunk);

  // Format hunks
  for (const hunk of hunks) {
    lines.push(`@@ -${hunk.oldStart},${hunk.oldLen} +${hunk.newStart},${hunk.newLen} @@`);
    lines.push(...hunk.lines);
  }

  return lines.join("\n");
}

/** Compute Longest Common Subsequence of two line arrays. */
function computeLCS(a: string[], b: string[]): string[] {
  const m = a.length, n = b.length;
  // Use space-optimized approach for large files
  if (m > 10000 || n > 10000) {
    // Fallback to simple approach for very large files
    return simpleLCS(a, b);
  }

  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  // Backtrack
  const result: string[] = [];
  let i = m, j = n;
  while (i > 0 && j > 0) {
    if (a[i - 1] === b[j - 1]) {
      result.unshift(a[i - 1]);
      i--;
      j--;
    } else if (dp[i - 1][j] > dp[i][j - 1]) {
      i--;
    } else {
      j--;
    }
  }
  return result;
}

function simpleLCS(a: string[], b: string[]): string[] {
  // Simple greedy match for large files
  const result: string[] = [];
  let j = 0;
  for (let i = 0; i < a.length && j < b.length; i++) {
    if (a[i] === b[j]) {
      result.push(a[i]);
      j++;
    }
  }
  return result;
}

export async function runDiff(fileA: string, fileB: string): Promise<void> {
  let textA: string, textB: string;
  try {
    textA = readFileSync(fileA, "utf-8");
  } catch {
    console.error(`Error: Cannot read file: ${fileA}`);
    process.exitCode = 1;
    return;
  }
  try {
    textB = readFileSync(fileB, "utf-8");
  } catch {
    console.error(`Error: Cannot read file: ${fileB}`);
    process.exitCode = 1;
    return;
  }

  if (textA === textB) {
    console.log("Files are identical.");
    return;
  }

  const output = unifiedDiff(textA, textB, fileA, fileB);
  console.log(output);
}

export const diffCommand = new Command("diff")
  .description("Compare two YAML files")
  .argument("<a>", "First file")
  .argument("<b>", "Second file")
  .action(async (a, b) => {
    await runDiff(a, b);
  });
