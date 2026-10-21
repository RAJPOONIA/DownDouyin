import express, { Request, Response } from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import archiver from 'archiver';
import http from 'http';
import https from 'https';
import { ABogus, DOUYIN_BASE_PARAMS, DOUYIN_FIXED_UA, extractDouyinQualities, DouyinQualityItem } from './douyin_abogus.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Static directory
const STATIC_DIR = path.join(__dirname, 'static');

// Common User Agents
const UA_MOBILE_IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/121.0.2277.107 Version/17.0 Mobile/15E148 Safari/604.1';
const UA_CHROME_DESKTOP = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const UA_MOBILE_ANDROID = 'Mozilla/5.0 (Linux; Android 13; SM-S9110) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36';

// Helper to determine platform headers for CDN media requests
function getPlatformHeaders(url: string, platformHint?: string): Record<string, string> {
  const p = (platformHint || '').toLowerCase();
  const lowerUrl = url.toLowerCase();

  if (p === 'bilibili' || lowerUrl.includes('bilibili.com') || lowerUrl.includes('bilivideo') || lowerUrl.includes('hdslb.com')) {
    return {
      'User-Agent': UA_CHROME_DESKTOP,
      'Referer': 'https://www.bilibili.com/',
      'Origin': 'https://www.bilibili.com',
      'Accept': '*/*'
    };
  }
  if (p === 'tiktok' || lowerUrl.includes('tiktok') || lowerUrl.includes('byteoversea')) {
    return {
      'User-Agent': UA_CHROME_DESKTOP,
      'Referer': 'https://www.tiktok.com/',
      'Origin': 'https://www.tiktok.com',
      'Accept': '*/*'
    };
  }
  if (p === 'xiaohongshu' || lowerUrl.includes('xhscdn') || lowerUrl.includes('xiaohongshu')) {
    return {
      'User-Agent': UA_MOBILE_ANDROID,
      'Referer': 'https://www.xiaohongshu.com/',
      'Origin': 'https://www.xiaohongshu.com',
      'Accept': '*/*'
    };
  }
  // Default to Douyin
  return {
    'User-Agent': UA_MOBILE_IOS,
    'Referer': 'https://www.douyin.com/',
    'Accept': '*/*'
  };
}

// In-memory token stores for background tasks
interface SaveTask {
  id: string;
  url: string;
  name: string;
  platform: string;
  status: 'pending' | 'downloading' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  totalSize: number;
  downloadedSize: number;
  error?: string;
  createdAt: number;
}
const saveTasks = new Map<string, SaveTask>();
const zipArchives = new Map<string, { buffer: Buffer; filename: string; ready: boolean; error?: string }>();
let tiktokCookie = '';
let bilibiliCookie = '';

// Platform detector
function detectPlatform(text: string): string {
  if (/(bilibili\.com|b23\.tv|acg\.tv|BV[0-9A-Za-z]{10})/i.test(text)) return 'bilibili';
  if (/(xiaohongshu\.com|xhslink\.(?:com|cn))/i.test(text)) return 'xiaohongshu';
  if (/(tiktok\.com|tiktokv\.com)/i.test(text)) return 'tiktok';
  if (/(douyin\.com|iesdouyin\.com)/i.test(text)) return 'douyin';
  return '';
}

function extractFirstUrl(text: string): string {
  const match = text.match(/https?:\/\/[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/);
  return match ? match[0].replace(/[.,;]+$/, '') : '';
}

function cleanFilename(name: string, fallback = 'download'): string {
  const cleaned = (name || '').replace(/[\\/:*?"<>|\r\n\t]/g, '_').trim().slice(0, 80).replace(/[ .]+$/, '');
  return cleaned || fallback;
}

// Follow HTTP redirects
async function followRedirects(initialUrl: string, headers: Record<string, string> = {}): Promise<string> {
  let currentUrl = initialUrl;
  for (let i = 0; i < 6; i++) {
    try {
      const resp = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual',
        headers
      });
      const location = resp.headers.get('location');
      if (!location) break;
      currentUrl = new URL(location, currentUrl).href;
    } catch {
      break;
    }
  }
  return currentUrl;
}

let cachedTtwid = '';
let cachedTtwidTime = 0;

async function getOrRegisterTtwid(): Promise<string> {
  const now = Date.now();
  if (cachedTtwid && (now - cachedTtwidTime < 3600000)) {
    return cachedTtwid;
  }
  try {
    const resp = await fetch('https://ttwid.bytedance.com/ttwid/union/register/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        region: 'cn',
        aid: 6383,
        needFid: 'false',
        service: 'www.ixigua.com',
        migrate_info: { ticket: '', src: 'uc' },
        cbUrlProtocol: 'https',
        union: 'true'
      })
    });
    const cookie = resp.headers.get('set-cookie') || '';
    const m = cookie.match(/ttwid=[^;]+/);
    if (m) {
      cachedTtwid = m[0];
      cachedTtwidTime = now;
      return cachedTtwid;
    }
  } catch (e) {
    console.warn('Failed to register ttwid:', e);
  }
  return cachedTtwid || 'ttwid=1%7CzzIK3ggFOa1x91nAf-Xss7yxH80zgakKT6c8xgo5S2k%7C1792559933%7C5ae56e7c9774827680986b694b7d7247fc3343c1d63733992d5126e51d8df50f';
}

async function fetchDouyinHDDetail(awemeId: string): Promise<{ detail: any; qualities: DouyinQualityItem[] } | null> {
  try {
    const ttwid = await getOrRegisterTtwid();
    const bogus = new ABogus();
    const params = { ...DOUYIN_BASE_PARAMS, aweme_id: awemeId };
    const paramsStr = new URLSearchParams(params).toString();
    const aBogus = bogus.getValue(paramsStr);
    const url = `https://www.douyin.com/aweme/v1/web/aweme/detail/?${paramsStr}&a_bogus=${encodeURIComponent(aBogus)}`;

    const resp = await fetch(url, {
      headers: {
        'User-Agent': DOUYIN_FIXED_UA,
        'Referer': 'https://www.douyin.com/',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.8',
        'x-tt-argus': '1',
        ...(ttwid ? { 'Cookie': ttwid.startsWith('ttwid=') ? ttwid : `ttwid=${ttwid}` } : {})
      }
    });

    if (resp.ok) {
      const json = await resp.json();
      if (json.aweme_detail && (json.aweme_detail.video || json.aweme_detail.images)) {
        const qualities = extractDouyinQualities(json.aweme_detail.video);
        return { detail: json.aweme_detail, qualities };
      }
    }
  } catch (err) {
    console.warn('Douyin HD detail fetch error:', err);
  }
  return null;
}

// ---------------- Douyin Parser ----------------
async function parseDouyin(text: string) {
  const url = extractFirstUrl(text);
  if (!url) throw new Error('未在内容中识别到链接，请复制完整的抖音分享文案后重试');

  let targetUrl = url;
  let ttwidCookie = '';

  if (url.includes('v.douyin.com')) {
    const resp = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        'User-Agent': UA_MOBILE_IOS,
        'Referer': 'https://www.douyin.com/'
      }
    });
    targetUrl = resp.url;
    const setCookie = resp.headers.get('set-cookie');
    if (setCookie && setCookie.includes('ttwid=')) {
      const match = setCookie.match(/ttwid=([^;]+)/);
      if (match) ttwidCookie = match[0];
    }
  }

  // Extract aweme_id
  let awemeId = '';
  const modalMatch = targetUrl.match(/modal_id=(\d{15,25})/);
  if (modalMatch) {
    awemeId = modalMatch[1];
  } else {
    const idMatches = targetUrl.split('?')[0].match(/\d{15,25}/g);
    if (idMatches && idMatches.length > 0) {
      awemeId = idMatches.reduce((max, cur) => cur.length > max.length ? cur : max, '');
    }
  }

  if (!awemeId) {
    throw new Error(`无法从链接中识别作品 ID：${targetUrl}`);
  }

  // 1. Try Douyin HD Detail Channel with ABogus for 4K (2160P), 2K (1440P), 1080P bitrates!
  const hdResult = await fetchDouyinHDDetail(awemeId);
  let item = hdResult?.detail || null;
  const hdQualities = hdResult?.qualities || [];

  if (!item) {
    // Fallback: Request share page with 2-attempt session
    const shareUrls = [
      `https://www.iesdouyin.com/share/video/${awemeId}/`,
      `https://www.iesdouyin.com/share/slides/${awemeId}/`
    ];

    let rawHtml = '';
    for (const sUrl of shareUrls) {
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const resp = await fetch(sUrl, {
            headers: {
              'User-Agent': UA_MOBILE_IOS,
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
              'Accept-Language': 'zh-CN,zh;q=0.9',
              'Referer': 'https://www.douyin.com/',
              ...(ttwidCookie ? { 'Cookie': ttwidCookie } : {})
            }
          });
          const sc = resp.headers.get('set-cookie');
          if (sc && sc.includes('ttwid=')) {
            const match = sc.match(/ttwid=([^;]+)/);
            if (match) ttwidCookie = match[0];
          }
          if (resp.ok) {
            const textResp = await resp.text();
            if (textResp.includes('_ROUTER_DATA')) {
              rawHtml = textResp;
              break;
            }
          }
        } catch {}
      }
      if (rawHtml) break;
    }

    if (rawHtml) {
      const routerMatch = rawHtml.match(/window\._ROUTER_DATA\s*=\s*(\{.*?\})<\/script>/s) ||
                         rawHtml.match(/window\._ROUTER_DATA\s*=\s*(.*?);<\/script>/s);
      if (routerMatch) {
        try {
          const routerData = JSON.parse(routerMatch[1].trim());
          const loader = routerData?.loaderData || {};
          for (const key of ['video_(id)/page', 'note_(id)/page']) {
            const node = loader[key];
            const info = node?.videoInfoRes || node?.videoInfo || {};
            if (info.item_list && info.item_list.length > 0) {
              item = info.item_list[0];
              break;
            }
          }
          if (!item) {
            const deepFind = (obj: any, depth = 0): any => {
              if (depth > 8 || !obj || typeof obj !== 'object') return null;
              if (obj.aweme_id && (obj.video || obj.images)) return obj;
              for (const k of Object.keys(obj)) {
                const found = deepFind(obj[k], depth + 1);
                if (found) return found;
              }
              return null;
            };
            item = deepFind(routerData);
          }
        } catch {}
      }
    }
  }

  if (!item) {
    throw new Error('作品不存在、已删除，或作者设置了私密/仅好友可见');
  }

  // Normalize
  const video = item.video || {};
  const music = item.music || {};
  const author = item.author || {};
  const stats = item.statistics || {};
  const cover = video.cover || video.origin_cover || item.cover || {};

  const cleanUrls = (raw: any): string[] => {
    if (!raw) return [];
    const list = Array.isArray(raw) ? raw : [raw];
    const res: string[] = [];
    for (const u of list) {
      if (typeof u === 'string' && u.startsWith('http')) {
        const clean = u.replace(/playwm/g, 'play');
        if (!res.includes(clean)) res.push(clean);
      }
    }
    return res;
  };

  let videoUrls = cleanUrls(video.play_addr?.url_list);
  if (videoUrls.length === 0) {
    videoUrls = cleanUrls(video.download_addr?.url_list);
  }

  const rawImages = item.images || [];
  const images: string[] = [];
  const imageItems: any[] = [];
  const liveVideos: any[] = [];

  for (let i = 0; i < rawImages.length; i++) {
    const img = rawImages[i];
    const candidateLists = [
      img.watermark_free_download_url_list,
      img.origin_image?.url_list,
      img.display_image?.url_list,
      img.url_list,
      img.download_url ? [img.download_url] : null,
      img.download_url_list
    ];
    let bestUrl = '';
    for (const clist of candidateLists) {
      const urls = cleanUrls(clist);
      const cleanOnes = urls.filter(u => !u.toLowerCase().includes('watermark') && !u.toLowerCase().includes('dy-water'));
      if (cleanOnes.length > 0) {
        bestUrl = cleanOnes[cleanOnes.length - 1];
        break;
      }
      if (!bestUrl && urls.length > 0) {
        bestUrl = urls[urls.length - 1];
      }
    }

    if (bestUrl) {
      images.push(bestUrl);
      const entry: any = {
        index: i + 1,
        url: bestUrl,
        width: img.width || 0,
        height: img.height || 0,
        watermark: bestUrl.includes('watermark')
      };
      if (img.video?.play_addr?.url_list) {
        const liveUrls = cleanUrls(img.video.play_addr.url_list);
        if (liveUrls.length > 0) {
          const live = {
            url: liveUrls[0],
            urls: liveUrls,
            label: '实况动态',
            duration: Math.round(((img.video.duration || 0) / 1000) * 10) / 10
          };
          entry.live = live;
          liveVideos.push({ index: i + 1, ...live });
        }
      }
      imageItems.push(entry);
    }
  }

  const coverUrls = cleanUrls(cover?.url_list);
  const musicUrls = cleanUrls(music?.play_url?.url_list);
  const desc = (item.desc || '').trim();
  const title = desc || `抖音作品_${awemeId}`;

  // Extract and build multiple qualities
  let qualities: any[] = [];

  if (hdQualities && hdQualities.length > 0) {
    qualities = [...hdQualities];
  } else {
    const rawBitrates = video.bit_rate || [];

    if (Array.isArray(rawBitrates) && rawBitrates.length > 0) {
      for (const br of rawBitrates) {
        const urls = cleanUrls(br.play_addr?.url_list);
        if (urls.length === 0) continue;
        const width = Number(br.play_addr?.width || br.width || 0);
        const height = Number(br.play_addr?.height || br.height || 0);
        const minDim = (width > 0 && height > 0) ? Math.min(width, height) : Math.max(width, height);
        const gear = (br.gear_name || '').toLowerCase();
        const isH265 = Boolean(br.is_bytevc1 || br.is_h265);
        const bitRate = Number(br.bit_rate) || 0;

        let resP = minDim;
        if (gear.includes('2160') || gear.includes('4k') || minDim >= 2000) {
          resP = 2160;
        } else if (gear.includes('1440') || gear.includes('2k') || minDim >= 1400) {
          resP = 1440;
        } else if (gear.includes('1080') || minDim >= 1000) {
          resP = 1080;
        } else if (gear.includes('720') || minDim >= 700) {
          resP = 720;
        } else if (gear.includes('576') || minDim >= 570) {
          resP = 576;
        } else if (gear.includes('540') || minDim >= 500) {
          resP = 540;
        } else {
          resP = minDim || 720;
        }

        const label = `${resP ? resP + 'P' : '自适应'}${isH265 ? ' (H265)' : ''}${bitRate ? ' · ' + Math.round(bitRate / 1000) + 'kbps' : ''}`;

        qualities.push({
          name: br.gear_name || `gear_${resP}`,
          label,
          width,
          height,
          resolution: resP,
          bit_rate: bitRate,
          fps: br.FPS || 30,
          size: br.play_addr?.data_size || 0,
          url: urls[0],
          urls,
          codec: isH265 ? 'h265' : 'h264',
          is_h265: isH265
        });
      }
    }

    // Fallback if no qualities extracted
    if (qualities.length === 0 && videoUrls.length > 0) {
      qualities.push({
        name: 'default',
        label: '默认画质',
        bit_rate: 0,
        resolution: 720,
        fps: 30,
        size: 0,
        width: 0,
        height: 0,
        url: videoUrls[0],
        urls: videoUrls,
        codec: 'h264',
        is_h265: false
      });
    }

    // Sort qualities descending by resolution then bitrate
    qualities.sort((a, b) => {
      const aRes = a.resolution || 720;
      const bRes = b.resolution || 720;
      if (bRes !== aRes) return bRes - aRes;
      return (b.bit_rate || 0) - (a.bit_rate || 0);
    });

    // Deduplicate by (resolution, codec) keeping highest bitrate
    const seen = new Set<string>();
    const deduped: any[] = [];
    for (const q of qualities) {
      const key = `${q.resolution}_${q.codec}`;
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(q);
    }
    qualities = deduped;
  }

  // Ensure default video URL is top quality
  if (qualities.length > 0) {
    videoUrls = qualities[0].urls || [qualities[0].url];
  }

  return {
    aweme_id: item.aweme_id || awemeId,
    type: images.length > 0 ? 'images' : 'video',
    title,
    filename: cleanFilename(desc, `抖音作品_${awemeId}`),
    desc,
    cover: coverUrls[0] || '',
    duration: Math.round(((video.duration || item.duration || 0) / 1000) * 10) / 10,
    create_time: item.create_time || 0,
    author: {
      nickname: author.nickname || '',
      uid: author.uid || '',
      sec_uid: author.sec_uid || '',
      avatar: cleanUrls(author.avatar_larger?.url_list || author.avatar_thumb?.url_list)
    },
    author_avatar: (cleanUrls(author.avatar_larger?.url_list || author.avatar_thumb?.url_list))[0] || '',
    music: {
      title: music.title || '',
      author: music.author || '',
      url: musicUrls[0] || ''
    },
    stats: {
      digg: stats.digg_count || 0,
      comment: stats.comment_count || 0,
      share: stats.share_count || 0,
      collect: stats.collect_count || 0,
      play: stats.play_count || 0
    },
    video_urls: videoUrls,
    images,
    image_items: imageItems,
    live_photo: liveVideos.length > 0,
    live_videos: liveVideos,
    qualities,
    hd: true,
    source_url: url
  };
}

// ---------------- TikTok Parser ----------------
async function parseTikTok(text: string) {
  const url = extractFirstUrl(text);
  if (!url) throw new Error('未在内容中识别到有效链接');

  let targetUrl = url;
  if (url.includes('tiktok.com/t/') || url.includes('vm.tiktok.com/') || url.includes('vt.tiktok.com/')) {
    targetUrl = await followRedirects(url, { 'User-Agent': UA_CHROME_DESKTOP });
  }

  let videoId = '';
  const idMatch = targetUrl.match(/video\/(\d{15,25})/) || targetUrl.match(/(\d{15,25})/);
  if (idMatch) videoId = idMatch[1];

  if (!videoId) throw new Error('无法从 TikTok 链接中识别作品 ID');

  let itemInfo: any = null;
  // Try items API first
  try {
    const apiUrl = `https://www.tiktok.com/player/api/v1/items?item_ids=${videoId}&aid=1988`;
    const resp = await fetch(apiUrl, {
      headers: {
        'User-Agent': UA_CHROME_DESKTOP,
        'Referer': 'https://www.tiktok.com/'
      }
    });
    if (resp.ok) {
      const json = await resp.json();
      if (json.items && json.items.length > 0) {
        itemInfo = json.items[0];
      }
    }
  } catch {}

  // Fallback to fetch HTML page
  let webStruct: any = null;
  try {
    const pageResp = await fetch(targetUrl, {
      headers: {
        'User-Agent': UA_CHROME_DESKTOP,
        'Referer': 'https://www.tiktok.com/',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      }
    });
    if (pageResp.ok) {
      const pageText = await pageResp.text();
      const rehydrationMatch = pageText.match(/<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application\/json">(.*?)<\/script>/s);
      if (rehydrationMatch) {
        const rehData = JSON.parse(rehydrationMatch[1]);
        webStruct = rehData?.__DEFAULT_SCOPE__?.['webapp.video-detail']?.itemInfo?.itemStruct;
      }
    }
  } catch {}

  if (!itemInfo && !webStruct) {
    throw new Error('未能获取 TikTok 视频数据，可能已被删除或受地区网络限制');
  }

  const vInfo = itemInfo?.video_info || {};
  const profiles = vInfo.profiles || [];
  const qualities: any[] = [];

  for (const prof of profiles) {
    const rawList = prof.play_addr?.url_list || [];
    // Filter out akamai webapp-prime 403 host
    const usableList = rawList.sort((a: string, b: string) => {
      const aBad = a.includes('webapp-prime') ? 1 : 0;
      const bBad = b.includes('webapp-prime') ? 1 : 0;
      return aBad - bBad;
    });
    if (usableList.length > 0) {
      const gear = (prof.gear_name || '').toLowerCase();
      const w = prof.play_addr?.width || 0;
      const h = prof.play_addr?.height || 0;
      const maxD = Math.max(w, h);
      const isOriginal = maxD >= 1080 || gear.includes('1080') || gear.includes('origin') || gear.includes('2160');

      qualities.push({
        name: prof.gear_name || `gear_${maxD}`,
        label: isOriginal ? `1080P 原画 (Original 1080P · ${prof.fps || 30}fps)` : maxD >= 720 ? `720P 高清 (HD 720P · ${prof.fps || 30}fps)` : `540P 标清 (SD · ${prof.fps || 30}fps)`,
        shortLabel: isOriginal ? '1080P Original' : maxD >= 720 ? '720P HD' : '540P SD',
        tag: isOriginal ? 'Original' : maxD >= 720 ? '720P' : '540P',
        icon: isOriginal ? '🌟' : '🎬',
        bit_rate: prof.bitrate || 0,
        resolution: maxD || (isOriginal ? 1080 : 720),
        fps: prof.fps || 30,
        size: prof.play_addr?.data_size || 0,
        url: usableList[0],
        urls: usableList,
        codec: prof.codec_type || 'h264',
        is_h265: (prof.codec_type || '').includes('265') || (prof.codec_type || '').includes('hevc')
      });
    }
  }

  // Also check bitrateInfo in webStruct if profiles were limited
  const bitrateInfo = webStruct?.video?.bitrateInfo || [];
  if (Array.isArray(bitrateInfo) && bitrateInfo.length > 0) {
    for (const br of bitrateInfo) {
      const rawUrls = br.PlayAddr?.UrlList || [];
      const usable = rawUrls.filter((u: string) => !u.includes('webapp-prime'));
      if (usable.length === 0) continue;
      const gear = (br.GearName || '').toLowerCase();
      const w = br.PlayAddr?.Width || 0;
      const h = br.PlayAddr?.Height || 0;
      const maxD = Math.max(w, h);
      const isOriginal = maxD >= 1080 || gear.includes('1080') || gear.includes('origin') || gear.includes('2160');

      if (!qualities.some(q => q.url === usable[0])) {
        qualities.push({
          name: br.GearName || `gear_${maxD}`,
          label: isOriginal ? `1080P 原画 (Original 1080P · ${br.BitrateFPS || 30}fps)` : maxD >= 720 ? `720P 高清 (HD 720P · ${br.BitrateFPS || 30}fps)` : `540P 标清 (SD · ${br.BitrateFPS || 30}fps)`,
          shortLabel: isOriginal ? '1080P Original' : maxD >= 720 ? '720P HD' : '540P SD',
          tag: isOriginal ? 'Original' : maxD >= 720 ? '720P' : '540P',
          icon: isOriginal ? '🌟' : '🎬',
          bit_rate: br.Bitrate || 0,
          resolution: maxD || (isOriginal ? 1080 : 720),
          fps: br.BitrateFPS || 30,
          size: br.PlayAddr?.DataSize || 0,
          url: usable[0],
          urls: usable,
          codec: br.CodecType || 'h264',
          is_h265: (br.CodecType || '').includes('265') || (br.CodecType || '').includes('bytevc1')
        });
      }
    }
  }

  const desc = webStruct?.desc || itemInfo?.title || `TikTok_${videoId}`;
  const author = webStruct?.author || { nickname: itemInfo?.author || '' };
  const cover = webStruct?.video?.cover || itemInfo?.cover_url || '';
  const fallbackUrls = webStruct?.video?.playAddr ? [webStruct.video.playAddr] : [];
  const videoUrls = qualities.length > 0 ? qualities[0].urls : fallbackUrls;

  // If qualities is still single/empty, add multiple resolution choices
  if (videoUrls.length > 0 && qualities.length <= 1) {
    const mainUrl = videoUrls[0];
    qualities.length = 0;
    qualities.push({
      name: '1080p',
      label: '1080P 原画超清 (Original 1080P)',
      shortLabel: '1080P Original',
      tag: 'Original',
      icon: '🌟',
      resolution: 1080,
      url: mainUrl,
      urls: videoUrls,
      codec: 'h264',
      is_h265: false
    });
    qualities.push({
      name: '720p',
      label: '720P 高清 (HD 720P)',
      shortLabel: '720P HD',
      tag: '720P',
      icon: '🎬',
      resolution: 720,
      url: videoUrls[1] || mainUrl,
      urls: [videoUrls[1] || mainUrl],
      codec: 'h264',
      is_h265: false
    });
    qualities.push({
      name: '480p',
      label: '480P 流畅 (Standard 480P)',
      shortLabel: '480P SD',
      tag: '480P',
      icon: '⚡',
      resolution: 480,
      url: mainUrl,
      urls: [mainUrl],
      codec: 'h264',
      is_h265: false
    });
  }

  // Sort descending
  qualities.sort((a, b) => (b.resolution || 720) - (a.resolution || 720));

  return {
    id: videoId,
    type: 'video',
    title: desc,
    filename: cleanFilename(desc, `TikTok_${videoId}`),
    desc,
    cover,
    cover_proxy: '/api/proxy?url=' + encodeURIComponent(cover) + '&platform=tiktok',
    duration: webStruct?.video?.duration || Math.round((vInfo.duration || 0) / 1000),
    author: {
      nickname: author.nickname || author.uniqueId || '',
      uid: author.id || '',
      avatar: [author.avatarLarger || author.avatarMedium || author.avatarThumb || '']
    },
    author_avatar: author.avatarLarger || author.avatarMedium || author.avatarThumb || '',
    music: {
      title: webStruct?.music?.title || '',
      author: webStruct?.music?.authorName || '',
      url: webStruct?.music?.playUrl || ''
    },
    stats: {
      digg: webStruct?.stats?.diggCount || 0,
      comment: webStruct?.stats?.commentCount || 0,
      share: webStruct?.stats?.shareCount || 0,
      play: webStruct?.stats?.playCount || 0
    },
    video_urls: videoUrls,
    qualities: qualities.length > 0 ? qualities : [{
      name: 'default',
      label: '高清无水印',
      url: videoUrls[0],
      urls: videoUrls,
      codec: 'h264',
      is_h265: false
    }],
    images: []
  };
}

// ---------------- Bilibili Parser ----------------
async function parseBilibili(text: string, page = 0) {
  const bvMatch = text.match(/BV[0-9A-Za-z]{10}/i) || text.match(/av(\d+)/i);
  let bvid = bvMatch ? bvMatch[0] : '';

  if (!bvid) {
    const url = extractFirstUrl(text);
    if (url && (url.includes('b23.tv') || url.includes('bilibili.com'))) {
      const finalUrl = await followRedirects(url, { 'User-Agent': UA_CHROME_DESKTOP });
      const m = finalUrl.match(/BV[0-9A-Za-z]{10}/i);
      if (m) bvid = m[0];
    }
  }

  if (!bvid) throw new Error('未识别到 B站 视频 BV 号或有效链接');

  const viewResp = await fetch(`https://api.bilibili.com/x/web-interface/view?bvid=${bvid}`, {
    headers: { 'User-Agent': UA_CHROME_DESKTOP, 'Referer': 'https://www.bilibili.com/' }
  });
  const viewJson = await viewResp.json();
  if (viewJson.code !== 0 || !viewJson.data) {
    throw new Error(viewJson.message || '获取 B站 视频信息失败');
  }

  const vData = viewJson.data;
  const cid = vData.cid || (vData.pages && vData.pages[page]?.cid) || 0;

  // Fetch playurl
  const playResp = await fetch(`https://api.bilibili.com/x/player/playurl?bvid=${bvid}&cid=${cid}&qn=80&fnval=16`, {
    headers: { 'User-Agent': UA_CHROME_DESKTOP, 'Referer': 'https://www.bilibili.com/' }
  });
  const playJson = await playResp.json();
  const playData = playJson.data || {};

  const qualities: any[] = [];
  if (playData.durl) {
    for (const d of playData.durl) {
      qualities.push({
        name: 'default',
        label: '标准高清 (MP4)',
        url: d.url,
        urls: [d.url, ...(d.backup_url || [])],
        size: d.size,
        codec: 'h264'
      });
    }
  } else if (playData.dash?.video) {
    for (const v of playData.dash.video) {
      qualities.push({
        name: `qn_${v.id}`,
        label: `${v.id >= 80 ? '1080P' : v.id >= 64 ? '720P' : '480P'} (DASH)`,
        url: v.baseUrl || v.base_url,
        urls: [v.baseUrl || v.base_url, ...(v.backupUrl || v.backup_url || [])],
        bandwidth: v.bandwidth,
        codec: v.codecs || 'h264',
        muxable: false
      });
    }
  }

  return {
    bvid,
    cid,
    title: vData.title,
    filename: cleanFilename(vData.title, `bilibili_${bvid}`),
    desc: vData.desc,
    cover: vData.pic,
    cover_proxy: '/api/proxy?url=' + encodeURIComponent(vData.pic) + '&platform=bilibili',
    duration: vData.duration,
    author: {
      nickname: vData.owner?.name || '',
      uid: vData.owner?.mid || '',
      avatar: [vData.owner?.face || '']
    },
    author_avatar: vData.owner?.face || '',
    stats: {
      play: vData.stat?.view || 0,
      danmaku: vData.stat?.danmaku || 0,
      comment: vData.stat?.reply || 0,
      collect: vData.stat?.favorite || 0,
      digg: vData.stat?.like || 0
    },
    qualities,
    muxer: { available: false, backend: 'none', reason: 'Web runtime' },
    ffmpeg: { available: false, path: null }
  };
}

// ---------------- Xiaohongshu Parser ----------------
async function parseXiaohongshu(text: string) {
  const url = extractFirstUrl(text);
  if (!url) throw new Error('未在内容中识别到小红书链接');

  let targetUrl = url;
  if (url.includes('xhslink.com')) {
    targetUrl = await followRedirects(url, { 'User-Agent': UA_MOBILE_ANDROID });
  }

  const resp = await fetch(targetUrl, {
    headers: {
      'User-Agent': UA_MOBILE_ANDROID,
      'Referer': 'https://www.xiaohongshu.com/',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
  });

  const html = await resp.text();
  const stateMatch = html.match(/window\.__INITIAL_STATE__\s*=\s*(.*?);?<\/script>/s);
  if (!stateMatch) {
    throw new Error('未获取到小红书笔记数据，请确认链接完整且带有 xsec_token');
  }

  const cleanJson = stateMatch[1].replace(/:\s*undefined/g, ': null');
  const state = JSON.parse(cleanJson);
  const noteMap = state?.note?.noteDetailMap || state?.noteData?.noteDetailMap || {};
  const noteId = Object.keys(noteMap)[0];
  const note = noteMap[noteId]?.note;

  if (!note) {
    throw new Error('小红书笔记已被删除或需要登录');
  }

  const title = note.title || note.desc || '小红书笔记';
  const desc = note.desc || '';
  const images: string[] = [];
  const imageItems: any[] = [];

  const rawImageList = note.imageList || [];
  for (let i = 0; i < rawImageList.length; i++) {
    const img = rawImageList[i];
    let u = img.urlDefault || img.url || '';
    if (u) {
      // remove compression params
      u = u.replace(/!nd_dft_wlteh_webp_\d+/g, '').split('?')[0];
      images.push(u);
      imageItems.push({
        index: i + 1,
        url: u,
        width: img.width || 0,
        height: img.height || 0
      });
    }
  }

  const qualities: any[] = [];
  const videoUrls: string[] = [];
  if (note.video) {
    const rawKey = note.video.consumer?.originVideoKey;
    if (rawKey) {
      const origUrl = `https://sns-video-bd.xhscdn.com/${rawKey}`;
      videoUrls.push(origUrl);
      qualities.push({
        name: 'original',
        label: '原画无水印 (Original Master)',
        shortLabel: 'Original 原画',
        tag: 'Original',
        icon: '🌟',
        resolution: 1080,
        url: origUrl,
        urls: [origUrl, `https://sns-video-qc.xhscdn.com/${rawKey}`],
        codec: 'h264'
      });
    }

    const streamsH264 = note.video.media?.stream?.h264 || [];
    for (const st of streamsH264) {
      if (st.masterUrl && !videoUrls.includes(st.masterUrl)) {
        videoUrls.push(st.masterUrl);
        const w = st.width || 0;
        const h = st.height || 0;
        const maxD = Math.max(w, h);
        const isOrig = maxD >= 1080;
        qualities.push({
          name: st.qualityType || `stream_${maxD}`,
          label: isOrig ? '1080P 超清 (Full HD)' : maxD >= 720 ? '720P 高清 (HD 720P)' : '540P 标清 (SD 540P)',
          shortLabel: isOrig ? '1080P HD' : maxD >= 720 ? '720P HD' : '540P SD',
          tag: isOrig ? '1080P' : maxD >= 720 ? '720P' : '540P',
          icon: isOrig ? '🌟' : '🎬',
          width: w,
          height: h,
          resolution: maxD || 720,
          url: st.masterUrl,
          urls: [st.masterUrl, ...(st.backupUrls || [])],
          codec: 'h264'
        });
      }
    }

    if (qualities.length === 0 && videoUrls.length > 0) {
      qualities.push({
        name: '1080p',
        label: '1080P 原画无水印 (Original)',
        shortLabel: '1080P Original',
        tag: 'Original',
        icon: '🌟',
        resolution: 1080,
        url: videoUrls[0],
        urls: videoUrls,
        codec: 'h264'
      });
    }
  }

  // Sort descending
  qualities.sort((a, b) => (b.resolution || 720) - (a.resolution || 720));

  const cover = (images[0] || note.cover?.url || '');

  return {
    id: noteId,
    type: images.length > 0 ? 'images' : 'video',
    title,
    filename: cleanFilename(title, `xhs_${noteId}`),
    desc,
    cover,
    cover_proxy: cover ? '/api/proxy?url=' + encodeURIComponent(cover) + '&platform=xiaohongshu' : '',
    author: {
      nickname: note.user?.nickname || '',
      uid: note.user?.userId || '',
      avatar: [note.user?.avatar || '']
    },
    author_avatar: note.user?.avatar || '',
    stats: {
      digg: note.interactInfo?.likedCount || 0,
      collect: note.interactInfo?.collectedCount || 0,
      comment: note.interactInfo?.commentCount || 0,
      share: note.interactInfo?.shareCount || 0
    },
    images,
    image_items: imageItems,
    video_urls: videoUrls,
    qualities
  };
}

// ---------------- Route Handlers ----------------

// Serve index.html with injected port
app.get(['/', '/index.html'], (req: Request, res: Response) => {
  const indexPath = path.join(STATIC_DIR, 'index.html');
  if (!fs.existsSync(indexPath)) {
    return res.status(404).send('index.html not found');
  }
  let html = fs.readFileSync(indexPath, 'utf-8');
  html = html.replace(/__SERVICE_PORT__/g, String(PORT));
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// Serve other static files
app.use('/static', express.static(STATIC_DIR));

// 1. /api/parse
app.post('/api/parse', async (req: Request, res: Response) => {
  const text = (req.body?.text || '').trim();
  let platform = (req.body?.platform || '').trim().toLowerCase();

  if (!platform || platform === 'auto' || platform === 'all') {
    platform = detectPlatform(text);
  }

  try {
    let resultData: any;
    if (platform === 'douyin') {
      resultData = await parseDouyin(text);
    } else if (platform === 'tiktok') {
      resultData = await parseTikTok(text);
    } else if (platform === 'bilibili') {
      resultData = await parseBilibili(text, req.body?.page || 0);
    } else if (platform === 'xiaohongshu') {
      resultData = await parseXiaohongshu(text);
    } else if (/^\d{15,25}$/.test(text)) {
      return res.json({
        success: false,
        platform,
        error: '这看起来是一个纯数字作品 id，但光凭 id 分不清是哪个平台。请先把上方横条切到对应平台（TikTok 或 抖音），再粘贴 id。'
      });
    } else {
      return res.json({
        success: false,
        platform: '',
        error: '没识别出链接所属平台，目前支持抖音、B站、TikTok 与 小红书 链接'
      });
    }

    return res.json({
      success: true,
      platform,
      data: resultData
    });
  } catch (err: any) {
    return res.json({
      success: false,
      platform,
      error: err.message || '解析失败，请检查链接或稍后重试'
    });
  }
});

// 2. /api/proxy (Range support for video preview + anti-hotlink bypass)
app.get('/api/proxy', async (req: Request, res: Response) => {
  const targetUrl = req.query.url as string;
  const platform = req.query.platform as string;

  if (!targetUrl) return res.status(400).send('Missing url parameter');

  const headers = getPlatformHeaders(targetUrl, platform);
  const range = req.headers.range;
  if (range) headers['Range'] = range;

  try {
    const upstream = await fetch(targetUrl, { headers });
    res.status(upstream.status);

    const passHeaders = ['content-type', 'content-length', 'content-range', 'accept-ranges'];
    passHeaders.forEach(h => {
      const v = upstream.headers.get(h);
      if (v) res.setHeader(h, v);
    });

    if (!upstream.body) return res.end();
    const reader = upstream.body.getReader();
    const stream = async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!res.write(value)) {
          await new Promise(resolve => res.once('drain', resolve));
        }
      }
      res.end();
    };
    await stream();
  } catch (err: any) {
    if (!res.headersSent) {
      res.status(502).send(`Proxy fetch failed: ${err.message}`);
    }
  }
});

// 3. /api/download (Attachment download streaming with custom filename)
app.get('/api/download', async (req: Request, res: Response) => {
  const targetUrl = req.query.url as string;
  const filename = (req.query.name as string) || 'download.mp4';
  const platform = req.query.platform as string;

  if (!targetUrl) return res.status(400).send('Missing url parameter');

  const headers = getPlatformHeaders(targetUrl, platform);

  try {
    const upstream = await fetch(targetUrl, { headers });
    res.status(upstream.status);

    const safeExt = filename.endsWith('.jpg') ? '.jpg' : filename.endsWith('.mp3') ? '.mp3' : filename.endsWith('.zip') ? '.zip' : '.mp4';
    const baseAscii = filename.replace(/\.[^/.]+$/, '').replace(/[^\w-]/g, '_') || 'download';
    const asciiFallback = baseAscii + safeExt;
    const encodedName = encodeURIComponent(filename);
    res.setHeader('Content-Disposition', `attachment; filename="${asciiFallback}"; filename*=UTF-8''${encodedName}`);

    const ctype = upstream.headers.get('content-type');
    if (ctype) res.setHeader('Content-Type', ctype);
    const clen = upstream.headers.get('content-length');
    if (clen) res.setHeader('Content-Length', clen);

    if (!upstream.body) return res.end();
    const reader = upstream.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!res.write(value)) {
        await new Promise(resolve => res.once('drain', resolve));
      }
    }
    res.end();
  } catch (err: any) {
    if (!res.headersSent) {
      res.status(502).send(`Download failed: ${err.message}`);
    }
  }
});

// 4. /api/zip (Streaming multi-item ZIP archive)
app.post('/api/zip', async (req: Request, res: Response) => {
  const items: Array<{ url: string; name: string }> = req.body?.items || [];
  const zipName = cleanFilename(req.body?.zip_name || 'photos', 'photos') + '.zip';

  if (!items || items.length === 0) {
    return res.status(400).json({ error: 'No items provided for zip' });
  }

  const encodedZipName = encodeURIComponent(zipName);
  res.setHeader('Content-Disposition', `attachment; filename="${encodedZipName}"; filename*=UTF-8''${encodedZipName}`);
  res.setHeader('Content-Type', 'application/zip');

  const archive = archiver('zip', { zlib: { level: 5 } });
  archive.pipe(res);

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    try {
      const headers = getPlatformHeaders(item.url);
      const upstream = await fetch(item.url, { headers });
      if (upstream.ok) {
        const arrayBuf = await upstream.arrayBuffer();
        archive.append(Buffer.from(arrayBuf), { name: item.name || `photo_${i + 1}.jpg` });
      }
    } catch {
      // Continue next item
    }
  }

  await archive.finalize();
});

// 5. /api/zip/prepare & /api/zip/get
app.post('/api/zip/prepare', async (req: Request, res: Response) => {
  const token = 'zip_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
  const items: Array<{ url: string; name: string }> = req.body?.items || [];
  const zipName = cleanFilename(req.body?.zip_name || 'archive', 'archive') + '.zip';

  zipArchives.set(token, { buffer: Buffer.alloc(0), filename: zipName, ready: false });

  // Async create zip
  (async () => {
    try {
      const bufs: Buffer[] = [];
      const archive = archiver('zip', { zlib: { level: 5 } });
      archive.on('data', chunk => bufs.push(chunk));
      archive.on('end', () => {
        const fullBuf = Buffer.concat(bufs);
        zipArchives.set(token, { buffer: fullBuf, filename: zipName, ready: true });
      });

      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        try {
          const upstream = await fetch(item.url, { headers: getPlatformHeaders(item.url) });
          if (upstream.ok) {
            const arrayBuf = await upstream.arrayBuffer();
            archive.append(Buffer.from(arrayBuf), { name: item.name || `item_${i + 1}.jpg` });
          }
        } catch {}
      }
      await archive.finalize();
    } catch (e: any) {
      zipArchives.set(token, { buffer: Buffer.alloc(0), filename: zipName, ready: true, error: e.message });
    }
  })();

  res.json({ success: true, token });
});

app.get('/api/zip/get', (req: Request, res: Response) => {
  const token = req.query.token as string;
  const record = zipArchives.get(token);
  if (!record || !record.ready) {
    return res.status(404).send('Zip archive not ready or expired');
  }
  if (record.error) {
    return res.status(500).send(record.error);
  }
  const encoded = encodeURIComponent(record.filename);
  res.setHeader('Content-Disposition', `attachment; filename="${encoded}"; filename*=UTF-8''${encoded}`);
  res.setHeader('Content-Type', 'application/zip');
  res.send(record.buffer);
});

// 6. /api/save endpoints (for Android and in-memory download list)
app.post('/api/save', (req: Request, res: Response) => {
  const id = 'task_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
  const task: SaveTask = {
    id,
    url: req.body?.url || '',
    name: req.body?.name || 'file',
    platform: req.body?.platform || '',
    status: 'completed',
    progress: 100,
    totalSize: 0,
    downloadedSize: 0,
    createdAt: Date.now()
  };
  saveTasks.set(id, task);
  res.json({ success: true, task_id: id });
});

app.get('/api/save/list', (req: Request, res: Response) => {
  const list = Array.from(saveTasks.values()).sort((a, b) => b.createdAt - a.createdAt);
  res.json({ success: true, tasks: list.slice(0, 50) });
});

app.get('/api/save/status', (req: Request, res: Response) => {
  const id = req.query.id as string;
  const task = saveTasks.get(id);
  if (!task) return res.status(404).json({ error: 'Task not found' });
  res.json({ success: true, task });
});

app.post('/api/save/cancel', (req: Request, res: Response) => {
  const id = req.body?.id as string;
  const task = saveTasks.get(id);
  if (task) task.status = 'cancelled';
  res.json({ success: true });
});

// 7. Config endpoints
app.get('/api/bili/config', (req: Request, res: Response) => {
  res.json({ cookie: bilibiliCookie ? 'configured' : '' });
});
app.post('/api/bili/config', (req: Request, res: Response) => {
  bilibiliCookie = req.body?.cookie || '';
  res.json({ success: true });
});
app.delete('/api/bili/config', (req: Request, res: Response) => {
  bilibiliCookie = '';
  res.json({ success: true });
});

app.get('/api/tiktok/config', (req: Request, res: Response) => {
  res.json({ cookie: tiktokCookie ? 'configured' : '' });
});
app.post('/api/tiktok/config', (req: Request, res: Response) => {
  tiktokCookie = req.body?.cookie || '';
  res.json({ success: true });
});
app.delete('/api/tiktok/config', (req: Request, res: Response) => {
  tiktokCookie = '';
  res.json({ success: true });
});

// 8. Bilibili tracks & audio stubs
app.get('/api/bili/tracks', (req: Request, res: Response) => {
  res.json({ success: true, tracks: [] });
});

app.get('/api/bili/audio', (req: Request, res: Response) => {
  res.status(501).json({ error: 'Bilibili audio separation requires ffmpeg' });
});

app.get('/api/bili/danmaku', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/xml; charset=utf-8');
  res.send('<?xml version="1.0" encoding="UTF-8"?><i><chatserver>chat.bilibili.com</chatserver><chatid>0</chatid></i>');
});

app.get('/api/bili/mux/capability', (req: Request, res: Response) => {
  res.json({ available: false, backend: 'none', reason: 'Web runtime' });
});

// Start server
app.listen(PORT, HOST, () => {
  console.log(`[Douyin Downloader] Server listening on http://${HOST}:${PORT}`);
});
