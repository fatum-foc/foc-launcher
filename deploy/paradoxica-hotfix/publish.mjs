import { createHash, verify } from "node:crypto";
import { readFile } from "node:fs/promises";

const repository = process.env.GITHUB_REPOSITORY;
const token = process.env.GITHUB_TOKEN;
const tag = "client-0.0.3";
const root = new URL("./", import.meta.url);
const canonicalManifestName = "stable.json";
const canonicalSignatureName = "stable.json.sig";
const backupManifestName = "stable-0.0.6-before-paradoxica-hotfix-20260822.json";
const backupSignatureName = `${backupManifestName}.sig`;
const oldParadoxicaHash = "11f2803d5b2b21af8b2904096001498576e4b904992923361e60add14471448e";
const expectedObjects = [
  {
    path: "mods/FoC-Paradoxica-1.1.2.jar",
    hash: "15e1ae51be2b5b62f0c9f66908fde1e47971b90d0a53ab06b47ebd9387ad9be5",
    size: 248157,
  },
  {
    path: "mods/FoC-Paradoxica-Sudden-Strike-Patch-1.0.1.jar",
    hash: "c6dbc7ca137bd8f93f8dbec1de4d9604d3c464a437fc787e59bb9a83dd1a70be",
    size: 4910,
  },
];

if (!repository || !token) throw new Error("GitHub Actions authorization is unavailable.");

const manifestBytes = await readFile(new URL("stable.json", root));
const signatureBytes = await readFile(new URL("stable.json.sig", root));
const publicKey = await readFile(new URL("launcher-manifest-public.pem", root), "utf8");
const manifest = JSON.parse(manifestBytes.toString("utf8"));

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function sameBytes(left, right) {
  return left.length === right.length && left.equals(right);
}

function verifyPair(data, signature, label) {
  if (signature.length !== 64) throw new Error(`${label}: signature is not 64 bytes.`);
  const valid = verify("sha256", data, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
  if (!valid) throw new Error(`${label}: ECDSA signature is invalid.`);
}

verifyPair(manifestBytes, signatureBytes, "Prepared manifest");
if (manifest.clientVersion !== "0.0.6") throw new Error("Prepared clientVersion must remain 0.0.6.");
if (!Array.isArray(manifest.files) || manifest.files.length !== 601) {
  throw new Error("Prepared manifest must contain exactly 601 files.");
}
if (manifest.files.some((file) => file.path === "mods/FoC-Paradoxica-1.1.1.jar")) {
  throw new Error("Prepared manifest still contains Paradoxica 1.1.1.");
}

const objectBytes = new Map();
for (const expected of expectedObjects) {
  const entry = manifest.files.filter((file) => file.path === expected.path);
  if (entry.length !== 1 || entry[0].sha256 !== expected.hash || entry[0].size !== expected.size) {
    throw new Error(`Prepared manifest has an invalid entry for ${expected.path}.`);
  }
  const bytes = await readFile(new URL(expected.hash, root));
  if (bytes.length !== expected.size || sha256(bytes) !== expected.hash) {
    throw new Error(`Prepared object failed integrity validation: ${expected.hash}`);
  }
  objectBytes.set(expected.hash, bytes);
}

async function request(url, options = {}) {
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "FoC-Paradoxica-safe-publisher",
    Authorization: `Bearer ${token}`,
    ...(options.headers ?? {}),
  };
  const response = await fetch(url, { ...options, headers, redirect: "follow" });
  if (!response.ok) {
    const detail = (await response.text()).slice(0, 500);
    throw new Error(`GitHub HTTP ${response.status} for ${options.method ?? "GET"} ${url}: ${detail}`);
  }
  return response;
}

async function requestJson(url, options) {
  return (await request(url, options)).json();
}

const release = await requestJson(`https://api.github.com/repos/${repository}/releases/tags/${tag}`);
const releaseId = release.id;

async function listAssets() {
  const result = [];
  for (let page = 1; ; page += 1) {
    const batch = await requestJson(
      `https://api.github.com/repos/${repository}/releases/${releaseId}/assets?per_page=100&page=${page}`,
    );
    result.push(...batch);
    if (batch.length < 100) return result;
  }
}

function getAsset(assets, name, optional = false) {
  const matches = assets.filter((asset) => asset.name === name);
  if (matches.length > 1) throw new Error(`Duplicate release asset: ${name}`);
  if (matches.length === 0) {
    if (optional) return null;
    throw new Error(`Missing release asset: ${name}`);
  }
  return matches[0];
}

async function downloadAsset(asset) {
  const response = await request(asset.url, { headers: { Accept: "application/octet-stream" } });
  return Buffer.from(await response.arrayBuffer());
}

async function deleteAsset(asset) {
  await request(`https://api.github.com/repos/${repository}/releases/assets/${asset.id}`, { method: "DELETE" });
}

async function uploadAsset(name, bytes) {
  const url = `https://uploads.github.com/repos/${repository}/releases/${releaseId}/assets?name=${encodeURIComponent(name)}`;
  return requestJson(url, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: bytes,
  });
}

async function renameAsset(asset, name) {
  return requestJson(`https://api.github.com/repos/${repository}/releases/assets/${asset.id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
}

async function ensureImmutableAsset(name, bytes) {
  let assets = await listAssets();
  let asset = getAsset(assets, name, true);
  if (!asset) asset = await uploadAsset(name, bytes);
  const remote = await downloadAsset(asset);
  if (!sameBytes(remote, bytes)) throw new Error(`Remote immutable asset differs: ${name}`);
  return asset;
}

async function replaceStage(name, bytes) {
  const existing = getAsset(await listAssets(), name, true);
  if (existing) await deleteAsset(existing);
  const asset = await uploadAsset(name, bytes);
  if (!sameBytes(await downloadAsset(asset), bytes)) throw new Error(`Staging upload differs: ${name}`);
  return asset;
}

async function publicDownload(name) {
  const url = `https://github.com/${repository}/releases/download/${tag}/${encodeURIComponent(name)}?verify=${Date.now()}`;
  const response = await fetch(url, { redirect: "follow", cache: "no-store" });
  if (!response.ok) throw new Error(`Public download failed for ${name}: HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

async function restore(previousManifestBytes, previousSignatureBytes) {
  let assets = await listAssets();
  for (const name of [canonicalSignatureName, canonicalManifestName]) {
    const asset = getAsset(assets, name, true);
    if (asset) await deleteAsset(asset);
    assets = await listAssets();
  }
  await uploadAsset(canonicalSignatureName, previousSignatureBytes);
  await uploadAsset(canonicalManifestName, previousManifestBytes);
  assets = await listAssets();
  const restoredManifest = await downloadAsset(getAsset(assets, canonicalManifestName));
  const restoredSignature = await downloadAsset(getAsset(assets, canonicalSignatureName));
  if (!sameBytes(restoredManifest, previousManifestBytes) || !sameBytes(restoredSignature, previousSignatureBytes)) {
    throw new Error("Automatic rollback bytes do not match the previous signed pair.");
  }
  verifyPair(restoredManifest, restoredSignature, "Restored manifest");
}

let assets = await listAssets();
const currentManifestAsset = getAsset(assets, canonicalManifestName);
const currentSignatureAsset = getAsset(assets, canonicalSignatureName);
const previousManifestBytes = await downloadAsset(currentManifestAsset);
const previousSignatureBytes = await downloadAsset(currentSignatureAsset);
verifyPair(previousManifestBytes, previousSignatureBytes, "Current public manifest");

if (sameBytes(previousManifestBytes, manifestBytes) && sameBytes(previousSignatureBytes, signatureBytes)) {
  for (const expected of expectedObjects) await ensureImmutableAsset(expected.hash, objectBytes.get(expected.hash));
  console.log("Paradoxica hotfix is already published and verified.");
  process.exit(0);
}

const previousManifest = JSON.parse(previousManifestBytes.toString("utf8"));
if (previousManifest.clientVersion !== "0.0.6") throw new Error("Current public clientVersion is not 0.0.6.");
const oldEntries = previousManifest.files.filter(
  (file) => file.path === "mods/FoC-Paradoxica-1.1.1.jar" && file.sha256 === oldParadoxicaHash,
);
if (oldEntries.length !== 1) throw new Error("Current public manifest does not contain the expected Paradoxica 1.1.1 object.");
if (previousManifest.files.some((file) => file.path.startsWith("mods/FoC-Paradoxica-Sudden-Strike-Patch-"))) {
  throw new Error("Current public manifest already contains an unexpected Sudden Strike patch.");
}
if (manifest.files.length !== previousManifest.files.length + 1) {
  throw new Error("Hotfix must replace one file and add exactly one patch file.");
}

await ensureImmutableAsset(backupManifestName, previousManifestBytes);
await ensureImmutableAsset(backupSignatureName, previousSignatureBytes);
for (const expected of expectedObjects) await ensureImmutableAsset(expected.hash, objectBytes.get(expected.hash));

const suffix = (process.env.GITHUB_SHA ?? Date.now().toString()).slice(0, 12);
const stageManifestName = `stable.json.next-paradoxica-${suffix}`;
const stageSignatureName = `stable.json.sig.next-paradoxica-${suffix}`;
const stageManifest = await replaceStage(stageManifestName, manifestBytes);
const stageSignature = await replaceStage(stageSignatureName, signatureBytes);

let switchStarted = false;
try {
  switchStarted = true;
  await deleteAsset(currentSignatureAsset);
  await renameAsset(stageSignature, canonicalSignatureName);
  await deleteAsset(currentManifestAsset);
  await renameAsset(stageManifest, canonicalManifestName);

  assets = await listAssets();
  const finalManifest = await downloadAsset(getAsset(assets, canonicalManifestName));
  const finalSignature = await downloadAsset(getAsset(assets, canonicalSignatureName));
  if (!sameBytes(finalManifest, manifestBytes) || !sameBytes(finalSignature, signatureBytes)) {
    throw new Error("Canonical signed pair differs after the switch.");
  }
  verifyPair(finalManifest, finalSignature, "Final public manifest");
  for (const expected of expectedObjects) {
    const remote = await downloadAsset(getAsset(assets, expected.hash));
    if (remote.length !== expected.size || sha256(remote) !== expected.hash) {
      throw new Error(`Final object verification failed: ${expected.hash}`);
    }
  }

  let publicVerified = false;
  for (let attempt = 1; attempt <= 10; attempt += 1) {
    try {
      const publicManifest = await publicDownload(canonicalManifestName);
      const publicSignature = await publicDownload(canonicalSignatureName);
      if (sameBytes(publicManifest, manifestBytes) && sameBytes(publicSignature, signatureBytes)) {
        verifyPair(publicManifest, publicSignature, "Anonymous public manifest");
        publicVerified = true;
        break;
      }
    } catch (error) {
      if (attempt === 10) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  if (!publicVerified) throw new Error("Anonymous public signed pair did not converge to the new bytes.");

  console.log(`Published client 0.0.6 hotfix: ${manifest.files.length} files.`);
  console.log(`Manifest SHA-256: ${sha256(manifestBytes)}`);
  console.log(`New objects: ${expectedObjects.map((entry) => entry.hash).join(", ")}`);
  console.log(`Old object retained for rollback: ${oldParadoxicaHash}`);
} catch (error) {
  if (switchStarted) {
    console.error("Publication verification failed; restoring the previous signed pair.");
    await restore(previousManifestBytes, previousSignatureBytes);
  }
  throw error;
}
