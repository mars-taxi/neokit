// ============================================================
// NeoKr - Cloudflare Pages Functions API Router
// Catch-all for all /api/* routes
// ============================================================

import {
  handleEncrypt, handleDecrypt, handleHash, handleHMAC,
  handleGenerateKey, handleGenerateSalt, handleGenerateIV,
  handleBase64Encode, handleBase64Decode,
  handleRSAGenerate, handleRSAEncrypt, handleRSADecrypt,
  jsonResponse, errorResponse
} from './_crypto.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // 只处理 /api/* 路径，其他交给静态文件
  if (!path.startsWith('/api/')) {
    return context.next();
  }

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  if (request.method !== 'POST') {
    return errorResponse('仅支持POST请求', 405);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('请求参数解析失败', 400);
  }

  const routes = {
    '/api/encrypt': handleEncrypt,
    '/api/decrypt': handleDecrypt,
    '/api/hash': handleHash,
    '/api/hmac': handleHMAC,
    '/api/generate-key': handleGenerateKey,
    '/api/generate-salt': handleGenerateSalt,
    '/api/generate-iv': handleGenerateIV,
    '/api/base64-encode': handleBase64Encode,
    '/api/base64-decode': handleBase64Decode,
    '/api/rsa-generate': handleRSAGenerate,
    '/api/rsa-encrypt': handleRSAEncrypt,
    '/api/rsa-decrypt': handleRSADecrypt,
  };

  const handler = routes[path];
  if (!handler) {
    return errorResponse('未找到', 404);
  }

  try {
    const result = await handler(body);
    return jsonResponse(result);
  } catch (e) {
    return errorResponse(e.message, 400);
  }
}
