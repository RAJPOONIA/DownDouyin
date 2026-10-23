import smCrypto from 'sm-crypto';
const sm3 = smCrypto.sm3;

export const DOUYIN_FIXED_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36';

const STR_TABLE: Record<string, string> = {
  s0: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
  s1: 'Dkdpgh4ZKsQB80/Mfvw36XI1R25+WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe=',
  s2: 'Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe=',
  s3: 'ckdp1h4ZKsUB80/Mfvw36XIgR25+WQAlEi7NLboqYTOPuzmFjJnryx9HVGDaStCe',
  s4: 'Dkdpgh2ZmsQB80/MfvV36XI1R45-WUAlEixNLwoqYTOPuzKFjJnry79HbGcaStCe'
};

const UA_CODE = [
  76, 98, 15, 131, 97, 245, 224, 133, 122, 199, 241, 166, 79, 34, 90, 191,
  128, 126, 122, 98, 66, 11, 14, 40, 49, 110, 110, 173, 67, 96, 138, 252
];

export class ABogus {
  private endString = 'cus';
  private uaCode = UA_CODE;
  private browser: string;
  private browserLen: number;
  private browserCode: number[];

  constructor(platform: string = 'Win32') {
    this.browser = this.generateBrowserInfo(platform);
    this.browserLen = this.browser.length;
    this.browserCode = this.charCodeAt(this.browser);
  }

  private generateBrowserInfo(platform: string = 'Win32'): string {
    const innerWidth = 1920;
    const innerHeight = 1080;
    const outerWidth = 1920;
    const outerHeight = 1080;
    const valueList = [
      innerWidth, innerHeight, outerWidth, outerHeight,
      0, 0, 0, 0,
      outerWidth, outerHeight, outerWidth, outerHeight,
      innerWidth, innerHeight, 24, 24, platform
    ];
    return valueList.join('|');
  }

  private charCodeAt(s: string): number[] {
    return Array.from(s).map(c => c.charCodeAt(0));
  }

  private randomList(a: number | null, b = 170, c = 85, d = 0, e = 0, f = 0, g = 0): number[] {
    const r = a || Math.random() * 10000;
    const v = [r, Math.floor(r) & 255, Math.floor(r) >> 8];
    v.push((v[1] & b) | d);
    v.push((v[1] & c) | e);
    v.push((v[2] & b) | f);
    v.push((v[2] & c) | g);
    return v.slice(-4);
  }

  private list1(r: number | null) { return this.randomList(r, 170, 85, 1, 2, 5, 45 & 170); }
  private list2(r: number | null) { return this.randomList(r, 170, 85, 1, 0, 0, 0); }
  private list3(r: number | null) { return this.randomList(r, 170, 85, 1, 0, 5, 0); }

  private fromCharCodes(codes: number[]): string {
    return String.fromCharCode(...codes);
  }

  private generateString1(r1: number | null = null, r2: number | null = null, r3: number | null = null): string {
    return this.fromCharCodes(this.list1(r1)) +
           this.fromCharCodes(this.list2(r2)) +
           this.fromCharCodes(this.list3(r3));
  }

  private sm3ToArray(data: string | number[]): number[] {
    let inputStr: string;
    if (typeof data === 'string') {
      inputStr = data;
    } else {
      inputStr = Buffer.from(data).toString('binary');
    }
    const hex = sm3(inputStr);
    const arr: number[] = [];
    for (let i = 0; i < hex.length; i += 2) {
      arr.push(parseInt(hex.substring(i, i + 2), 16));
    }
    return arr;
  }

  private generateMethodCode(method = 'GET'): number[] {
    return this.sm3ToArray(this.sm3ToArray(method + this.endString));
  }

  private generateParamsCode(params: string): number[] {
    return this.sm3ToArray(this.sm3ToArray(params + this.endString));
  }

  private list4(a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, m: number, n: number, o: number, p: number, q: number, r: number): number[] {
    return [
      44, a, 0, 0, 0, 0, 24, b, n, 0, c, d, 0, 0, 0, 1, 0, 239,
      e, o, f, g, 0, 0, 0, 0, h, 0, 0, 14, i, j, 0, k, m, 3, p, 1, q, 1, r, 0, 0, 0
    ];
  }

  private endCheckNum(arr: number[]): number {
    let r = 0;
    for (const n of arr) r ^= n;
    return r;
  }

  private rc4Encrypt(plaintext: string, key: string): string {
    const s = Array.from({ length: 256 }, (_, i) => i);
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
      const tmp = s[i];
      s[i] = s[j];
      s[j] = tmp;
    }
    let i = 0;
    j = 0;
    const cipher: string[] = [];
    for (let k = 0; k < plaintext.length; k++) {
      i = (i + 1) % 256;
      j = (j + s[i]) % 256;
      const tmp = s[i];
      s[i] = s[j];
      s[j] = tmp;
      const t = (s[i] + s[j]) % 256;
      cipher.push(String.fromCharCode(s[t] ^ plaintext.charCodeAt(k)));
    }
    return cipher.join('');
  }

  private generateString2List(urlParams: string, method = 'GET', startTime = 0, endTime = 0): number[] {
    startTime = startTime || Date.now();
    endTime = endTime || (startTime + Math.floor(Math.random() * 5) + 4);
    const paramsArray = this.generateParamsCode(urlParams);
    const methodArray = this.generateMethodCode(method);

    return this.list4(
      (endTime >> 24) & 255,
      paramsArray[21],
      this.uaCode[23],
      (endTime >> 16) & 255,
      paramsArray[22],
      this.uaCode[24],
      (endTime >> 8) & 255,
      (endTime >> 0) & 255,
      (startTime >> 24) & 255,
      (startTime >> 16) & 255,
      (startTime >> 8) & 255,
      (startTime >> 0) & 255,
      methodArray[21],
      methodArray[22],
      Math.floor(endTime / (256 * 256 * 256 * 256)) >> 0,
      Math.floor(startTime / (256 * 256 * 256 * 256)) >> 0,
      this.browserLen
    );
  }

  private generateString2(urlParams: string, method = 'GET', startTime = 0, endTime = 0): string {
    const a = this.generateString2List(urlParams, method, startTime, endTime);
    const e = this.endCheckNum(a);
    a.push(...this.browserCode);
    a.push(e);
    return this.rc4Encrypt(this.fromCharCodes(a), 'y');
  }

  private generateResult(s: string, alphabetName: 's0' | 's1' | 's2' | 's3' | 's4' = 's4'): string {
    const alphabet = STR_TABLE[alphabetName];
    const r: string[] = [];
    for (let i = 0; i < s.length; i += 3) {
      let n: number;
      if (i + 2 < s.length) {
        n = (s.charCodeAt(i) << 16) | (s.charCodeAt(i + 1) << 8) | s.charCodeAt(i + 2);
      } else if (i + 1 < s.length) {
        n = (s.charCodeAt(i) << 16) | (s.charCodeAt(i + 1) << 8);
      } else {
        n = s.charCodeAt(i) << 16;
      }

      const bitShifts = [18, 12, 6, 0];
      const bitMasks = [0xFC0000, 0x03F000, 0x0FC0, 0x3F];
      for (let idx = 0; idx < 4; idx++) {
        const j = bitShifts[idx];
        const k = bitMasks[idx];
        if (j === 6 && i + 1 >= s.length) break;
        if (j === 0 && i + 2 >= s.length) break;
        r.push(alphabet[(n & k) >> j]);
      }
    }
    const pad = (4 - (r.length % 4)) % 4;
    r.push('='.repeat(pad));
    return r.join('');
  }

  public getValue(urlParams: Record<string, any> | string, method = 'GET'): string {
    let paramsStr = '';
    if (typeof urlParams === 'object') {
      paramsStr = new URLSearchParams(urlParams).toString();
    } else {
      paramsStr = urlParams;
    }
    const str1 = this.generateString1();
    const str2 = this.generateString2(paramsStr, method);
    return this.generateResult(str1 + str2, 's4');
  }
}

export const DOUYIN_BASE_PARAMS: Record<string, any> = {
  device_platform: 'webapp',
  aid: '6383',
  channel: 'channel_pc_web',
  pc_client_type: 1,
  version_code: '290100',
  version_name: '29.1.0',
  cookie_enabled: 'true',
  screen_width: 1920,
  screen_height: 1080,
  browser_language: 'zh-CN',
  browser_platform: 'Win32',
  browser_name: 'Chrome',
  browser_version: '130.0.0.0',
  browser_online: 'true',
  engine_name: 'Blink',
  engine_version: '130.0.0.0',
  os_name: 'Windows',
  os_version: '10',
  cpu_core_num: 12,
  device_memory: 8,
  platform: 'PC',
  downlink: '10',
  effective_type: '4g',
  from_user_page: '1',
  locate_query: 'false',
  need_time_list: '1',
  pc_libra_divert: 'Windows',
  publish_video_strategy_type: '2',
  round_trip_time: '0',
  show_live_replay_strategy: '1',
  time_list_query: '0',
  whale_cut_token: '',
  msToken: ''
};

export interface DouyinQualityItem {
  name: string;
  label: string;
  shortLabel: string;
  tag: string;
  icon: string;
  resolution: number;
  bit_rate: number;
  fps: number;
  size: number;
  width: number;
  height: number;
  url: string;
  urls: string[];
  codec: 'h265' | 'h264';
  is_h265: boolean;
}

export function scoreDouyinCdnUrl(u: string): number {
  const lower = u.toLowerCase();
  let score = 30;

  if (lower.includes('v3-web.douyinvod.com') || lower.includes('v16-web.douyinvod.com') || lower.includes('v95-web.douyinvod.com')) {
    score = 10;
  } else if (lower.includes('douyinvod.com')) {
    if (lower.includes('v26-web.douyinvod.com')) score = 35;
    else if (lower.includes('v9-web.douyinvod.com')) score = 45;
    else if (lower.includes('v5-web.douyinvod.com')) score = 55;
    else if (lower.includes('v6-web.douyinvod.com')) score = 65;
    else if (lower.includes('v11-web.douyinvod.com')) score = 75;
    else score = 20;
  } else if (lower.includes('/aweme/v1/play')) {
    score = 25;
  }

  // Prefer HTTPS URLs over plain HTTP
  if (lower.startsWith('http://')) {
    score += 8;
  }

  // Avoid watermarked or degraded endpoints unless no clean alternative exists
  if (lower.includes('playwm') || lower.includes('watermark') || lower.includes('dy-water') || lower.includes('webapp-prime')) {
    score += 100;
  }

  return score;
}

function cleanUrls(raw: any): string[] {
  if (!raw) return [];
  const list = Array.isArray(raw) ? raw : [raw];
  const res: string[] = [];
  for (const u of list) {
    if (typeof u === 'string' && u.startsWith('http')) {
      let clean = u.trim().replace(/playwm/g, 'play').replace(/\/playwm\//g, '/play/');
      if (clean.startsWith('http://') && (clean.includes('douyinvod.com') || clean.includes('iesdouyin.com') || clean.includes('douyin.com'))) {
        clean = 'https://' + clean.slice(7);
      }
      if (!res.includes(clean)) res.push(clean);
    }
  }
  res.sort((a, b) => scoreDouyinCdnUrl(a) - scoreDouyinCdnUrl(b));
  return res;
}

function shortSide(playAddr: any): number {
  if (!playAddr || typeof playAddr !== 'object') return 0;
  const w = Number(playAddr.width) || 0;
  const h = Number(playAddr.height) || 0;
  if (w <= 0 || h <= 0) return 0;
  return Math.min(w, h);
}

function gearResolution(gearName: string): number {
  const m = gearName.match(/(?:^|_)(\d{3,4})(?:_|$)/);
  return m ? parseInt(m[1], 10) : 0;
}

export function extractDouyinQualities(video: any): DouyinQualityItem[] {
  const rawBitrates = video?.bit_rate || [];
  const list: DouyinQualityItem[] = [];

  for (const item of rawBitrates) {
    if (!item || typeof item !== 'object') continue;
    const gear = item.gear_name || '';
    const playAddr = item.play_addr || {};
    const urls = cleanUrls(playAddr.url_list);
    if (urls.length === 0) continue;

    const resolution = shortSide(playAddr) || gearResolution(gear);
    const isH265 = Boolean(item.is_h265 || item.is_bytevc1);
    const bitRate = Number(item.bit_rate) || 0;
    const fps = Number(item.FPS) || 30;
    const width = Number(playAddr.width) || 0;
    const height = Number(playAddr.height) || 0;

    let resLabel = resolution ? `${resolution}P` : 'Auto';
    if (resolution >= 2160) resLabel = '2160P (4K)';
    else if (resolution >= 1440) resLabel = '1440P (2K)';
    else if (resolution >= 1080) resLabel = '1080P (FHD)';
    else if (resolution >= 720) resLabel = '720P (HD)';
    else if (resolution >= 540) resLabel = '576P (SD)';

    const codecTag = isH265 ? ' (H265)' : '';
    const kbps = bitRate ? ` · ${Math.round(bitRate / 1000)}kbps` : '';
    const label = `${resolution ? `${resolution}P` : 'Auto'}${codecTag}${kbps}`;
    const shortLabel = `${resolution ? `${resolution}P` : 'Auto'}${isH265 ? ' H265' : ''}`;

    let icon = '🎬';
    let tag = `${resolution || 720}P`;
    if (resolution >= 2160) {
      icon = '🌟';
      tag = '4K 2160P';
    } else if (resolution >= 1440) {
      icon = '✨';
      tag = '2K 1440P';
    } else if (resolution >= 1080) {
      icon = '💎';
      tag = '1080P';
    } else if (resolution >= 720) {
      icon = '🎬';
      tag = '720P';
    } else {
      icon = '📱';
      tag = 'SD';
    }

    list.push({
      name: gear || `gear_${resolution}`,
      label,
      shortLabel,
      tag,
      icon,
      resolution,
      bit_rate: bitRate,
      fps,
      size: Number(playAddr.data_size) || 0,
      width,
      height,
      url: urls[0],
      urls,
      codec: isH265 ? 'h265' : 'h264',
      is_h265: isH265
    });
  }

  // Sort descending by resolution, then bitrate
  list.sort((a, b) => {
    if (b.resolution !== a.resolution) return b.resolution - a.resolution;
    return b.bit_rate - a.bit_rate;
  });

  // Deduplicate: same (resolution, codec) keep highest bitrate
  const seen = new Set<string>();
  const deduped: DouyinQualityItem[] = [];
  for (const q of list) {
    const key = `${q.resolution}_${q.codec}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(q);
  }

  return deduped;
}
