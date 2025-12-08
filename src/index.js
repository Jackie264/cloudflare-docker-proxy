const dockerHub = "https://registry-1.docker.io";

function buildRoutes(env) {
  return {
    // production
    ["docker." + env.CUSTOM_DOMAIN]: dockerHub,
    ["quay." + env.CUSTOM_DOMAIN]: "https://quay.io",
    ["gcr." + env.CUSTOM_DOMAIN]: "https://gcr.io",
    ["k8s-gcr." + env.CUSTOM_DOMAIN]: "https://k8s.gcr.io",
    ["k8s." + env.CUSTOM_DOMAIN]: "https://registry.k8s.io",
    ["ghcr." + env.CUSTOM_DOMAIN]: "https://ghcr.io",
    ["cloudsmith." + env.CUSTOM_DOMAIN]: "https://docker.cloudsmith.io",
    ["ecr." + env.CUSTOM_DOMAIN]: "https://public.ecr.aws",

    // staging
    ["docker-staging." + env.CUSTOM_DOMAIN]: dockerHub,
  };
}

function routeByHosts(host, routes, env) {
  if (host in routes) {
    return routes[host];
  }
  if (env.MODE === "debug") {
    return env.TARGET_UPSTREAM;
  }
  return "";
}

async function handleRequest(request, env) {
  const url = new URL(request.url);

  // --- 🚀 新增 IP 校验逻辑 START ---
    const clientIP = request.headers.get("cf-connecting-ip");
    const allowedIPs = env.ALLOWED_IPS ? env.ALLOWED_IPS.split(",").map(ip => ip.trim()) : [];

    // 如果 ALLOWED_IPS 环境变量不为空，则进行 IP 检查
    if (allowedIPs.length > 0 && !allowedIPs.includes(clientIP)) {
        console.log(`Blocked unauthorized access from IP: ${clientIP}`);
        return new Response(JSON.stringify({ message: "Access Denied: Unauthorized IP Address" }), { status: 403 });
    }
    // --- 🚀 新增 IP 校验逻辑 END ---
  
  const routes = buildRoutes(env);

  if (url.pathname === "/") {
    return Response.redirect(url.protocol + "//" + url.host + "/v2/", 301);
  }

  const upstream = routeByHosts(url.hostname, routes, env);
  if (upstream === "") {
    return new Response(JSON.stringify({ routes }), { status: 404 });
  }

  const isDockerHub = upstream === dockerHub;
  let authorization = request.headers.get("Authorization");

  // 如果目标是 Docker Hub 且客户端没带认证，就用 Secret 注入
  if (isDockerHub && !authorization && env.DOCKER_USERNAME && env.DOCKER_PASSWORD) {
    const basicAuth = btoa(`${env.DOCKER_USERNAME}:${env.DOCKER_PASSWORD}`);
    authorization = `Basic ${basicAuth}`;
  }

  // /v2/ endpoint
  if (url.pathname === "/v2/") {
    const newUrl = new URL(upstream + "/v2/");
    const headers = new Headers();
    if (authorization) headers.set("Authorization", authorization);

    const resp = await fetch(newUrl.toString(), { method: "GET", headers, redirect: "follow" });
    if (resp.status === 401) return responseUnauthorized(url, env);
    return resp;
  }

  // /v2/auth endpoint
  if (url.pathname === "/v2/auth") {
    const newUrl = new URL(upstream + "/v2/");
    const resp = await fetch(newUrl.toString(), { method: "GET", redirect: "follow" });
    if (resp.status !== 401) return resp;

    const authenticateStr = resp.headers.get("WWW-Authenticate");
    if (!authenticateStr) return resp;

    const wwwAuthenticate = parseAuthenticate(authenticateStr);
    let scope = url.searchParams.get("scope");

    // autocomplete repo part into scope for DockerHub library images
    if (scope && isDockerHub) {
      let scopeParts = scope.split(":");
      if (scopeParts.length === 3 && !scopeParts[1].includes("/")) {
        scopeParts[1] = "library/" + scopeParts[1];
        scope = scopeParts.join(":");
      }
    }
    return await fetchToken(wwwAuthenticate, scope, authorization);
  }

  // redirect for DockerHub library images
  if (isDockerHub) {
    const pathParts = url.pathname.split("/");
    if (pathParts.length === 5) {
      pathParts.splice(2, 0, "library");
      const redirectUrl = new URL(url);
      redirectUrl.pathname = pathParts.join("/");
      return Response.redirect(redirectUrl, 301);
    }
  }

  // forward requests
  const newUrl = new URL(upstream + url.pathname);
  const headers = new Headers(request.headers);
  if (authorization) headers.set("Authorization", authorization);

  const newReq = new Request(newUrl, {
    method: request.method,
    headers,
    body: request.body,
    redirect: isDockerHub ? "manual" : "follow",
  });

  const resp = await fetch(newReq);
  if (resp.status === 401) return responseUnauthorized(url, env);

  // handle dockerhub blob redirect manually
  if (isDockerHub && resp.status === 307) {
    const location = new URL(resp.headers.get("Location"));
    const redirectResp = await fetch(location.toString(), { method: "GET", redirect: "follow" });
    return redirectResp;
  }

  return resp;
}

function parseAuthenticate(authenticateStr) {
  const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (!matches || matches.length < 2) {
    throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return { realm: matches[0], service: matches[1] };
}

async function fetchToken(wwwAuthenticate, scope, authorization) {
  const url = new URL(wwwAuthenticate.realm);
  if (wwwAuthenticate.service.length) url.searchParams.set("service", wwwAuthenticate.service);
  if (scope) url.searchParams.set("scope", scope);

  const headers = new Headers();
  if (authorization) headers.set("Authorization", authorization);

  return await fetch(url, { method: "GET", headers });
}

function responseUnauthorized(url, env) {
  const headers = new Headers();
  if (env.MODE === "debug") {
    headers.set("Www-Authenticate", `Bearer realm="http://${url.host}/v2/auth",service="cloudflare-docker-proxy"`);
  } else {
    headers.set("Www-Authenticate", `Bearer realm="https://${url.hostname}/v2/auth",service="cloudflare-docker-proxy"`);
  }
  return new Response(JSON.stringify({ message: "UNAUTHORIZED" }), { status: 401, headers });
}

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  }
};
