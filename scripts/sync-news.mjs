import { createPublicKey, verify } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const FEED_URL = process.env.FOC_NEWS_FEED_URL || 'http://fatumofcreation2.minerent.io:22173/v1/launcher/news';
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYKM1AJAe6Vc+URpFw0MXcwQ95Sm0
pjv+FXT62HVM4rkdV1Q6V4MAMnkrbM0jVdmyBtZP6f8u8WexEYdouZ3/mA==
-----END PUBLIC KEY-----`;
const ROOT = process.cwd();
const MEDIA_DIR = path.join(ROOT, 'news-media');
const MAX_FEED_BYTES = 4 * 1024 * 1024;
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const MAX_POSTS = 12;
const IMAGE_TYPES = new Map([['image/jpeg','.jpg'],['image/png','.png'],['image/webp','.webp'],['image/gif','.gif'],['image/avif','.avif']]);

const fetchRetry = async (url, attempts = 3) => {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const response = await fetch(url, { signal:AbortSignal.timeout(20_000), redirect:'follow' });
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      return response;
    } catch (error) {
      lastError = error;
      if (attempt < attempts) await new Promise(resolve => setTimeout(resolve, attempt * 1_000));
    }
  }
  throw lastError;
};
const safeText = (value, limit) => typeof value === 'string' ? value.slice(0, limit) : '';
const safeId = value => /^\d{6,24}$/.test(String(value || '')) ? String(value) : '';

const feedResponse = await fetchRetry(FEED_URL);
const rawFeed = Buffer.from(await feedResponse.arrayBuffer());
if (rawFeed.length > MAX_FEED_BYTES) throw new Error('News feed exceeds the size limit');
const signatureHeader = feedResponse.headers.get('x-foc-signature');
if (!signatureHeader) throw new Error('News feed signature is missing');
const authentic = verify('sha256', rawFeed, createPublicKey(PUBLIC_KEY), Buffer.from(signatureHeader, 'base64'));
if (!authentic) throw new Error('News feed signature is invalid');
const source = JSON.parse(rawFeed.toString('utf8'));
if (!source || !Array.isArray(source.posts)) throw new Error('News feed has an invalid schema');
await mkdir(MEDIA_DIR, { recursive:true });

const output = { version:1, channelName:safeText(source.channelName,100), updatedAt:safeText(source.updatedAt,64) || new Date().toISOString(), posts:[] };
for (const sourcePost of source.posts.slice(0, MAX_POSTS)) {
  const id = safeId(sourcePost.id);
  if (!id) continue;
  const post = {
    id,
    content:safeText(sourcePost.content,12000),
    authorName:safeText(sourcePost.authorName,120),
    publishedAt:safeText(sourcePost.publishedAt,64),
    discordUrl:/^https:\/\/discord\.com\/channels\/\d+\/\d+\/\d+$/.test(sourcePost.discordUrl || '') ? sourcePost.discordUrl : '',
    embeds:Array.isArray(sourcePost.embeds) ? sourcePost.embeds.slice(0,4).map(embed => ({ title:safeText(embed?.title,300), description:safeText(embed?.description,6000) })).filter(embed => embed.title || embed.description) : [],
    images:[]
  };
  for (const [index, attachment] of (Array.isArray(sourcePost.attachments) ? sourcePost.attachments.slice(0,4) : []).entries()) {
    const declaredType = safeText(attachment?.contentType,100).toLowerCase().split(';')[0];
    if (!IMAGE_TYPES.has(declaredType)) continue;
    const candidates = [];
    if (typeof attachment.imagePath === 'string' && /^\/v1\/launcher\/media\/\d+\/\d+$/.test(attachment.imagePath)) candidates.push(new URL(attachment.imagePath,FEED_URL).toString());
    if (typeof attachment.url === 'string' && attachment.url.startsWith('https://cdn.discordapp.com/attachments/')) candidates.push(attachment.url);
    for (const candidate of candidates) {
      try {
        const imageResponse = await fetchRetry(candidate,2);
        const actualType = (imageResponse.headers.get('content-type') || declaredType).toLowerCase().split(';')[0];
        const extension = IMAGE_TYPES.get(actualType);
        if (!extension) throw new Error(`Unsupported image type ${actualType}`);
        const bytes = Buffer.from(await imageResponse.arrayBuffer());
        if (!bytes.length || bytes.length > MAX_IMAGE_BYTES) throw new Error('Image exceeds the size limit');
        const fileName = `${id}-${index}${extension}`;
        await writeFile(path.join(MEDIA_DIR,fileName),bytes);
        post.images.push({ src:`./news-media/${fileName}`, alt:safeText(attachment.fileName,180) || 'Иллюстрация к новости' });
        break;
      } catch (error) {
        if (candidate === candidates.at(-1)) console.warn(`Image skipped for post ${id}: ${error.message}`);
      }
    }
  }
  output.posts.push(post);
}
if (!output.posts.length) throw new Error('Verified news feed contains no valid posts');
await writeFile(path.join(ROOT,'news.json'),JSON.stringify(output,null,2)+'\n','utf8');
console.log(`Synced ${output.posts.length} posts and ${output.posts.reduce((sum,post) => sum + post.images.length,0)} images.`);
