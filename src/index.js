export default {
  async fetch(request, env, ctx) {
    ctx.passThroughOnException();
    return handleRequest(request, env);
  },
};

const dockerHub = "https://registry-1.docker.io";

function buildRoutes(CUSTOM_DOMAIN) {
  return {
    // production
    ["docker." + CUSTOM_DOMAIN]: dockerHub,
    ["quay." + CUSTOM_DOMAIN]: "https://quay.io",
    ["gcr." + CUSTOM_DOMAIN]: "https://gcr.io",
    ["k8s-gcr." + CUSTOM_DOMAIN]: "https://k8s.gcr.io",
    ["k8s." + CUSTOM_DOMAIN]: "https://registry.k8s.io",
    ["ghcr." + CUSTOM_DOMAIN]: "https://ghcr.io",
    ["cloudsmith." + CUSTOM_DOMAIN]: "https://docker.cloudsmith.io",
    ["ecr." + CUSTOM_DOMAIN]: "https://public.ecr.aws",

    // staging
    ["docker-staging." + CUSTOM_DOMAIN]: dockerHub,
  };
}

function routeByHosts(host, routes, MODE, TARGET_UPSTREAM) {
  if (host in routes) {
    return routes[host];
  }
  if (MODE === "debug") {
    return TARGET_UPSTREAM;
  }
  return "";
}

async function handleRequest(request, env) {
  const { CUSTOM_DOMAIN, MODE, TARGET_UPSTREAM } = env;
  const routes = buildRoutes(CUSTOM_DOMAIN);

  const url = new URL(request.url);
  if (url.pathname === "/") {
    return Response.redirect(url.protocol + "//" + url.host + "/v2/", 301);
  }

  const upstream = routeByHosts(url.hostname, routes, MODE, TARGET_UPSTREAM);
  if (upstream === "") {
    return new Response(JSON.stringify({ routes }), { status: 404 });
  }

  const isDockerHub = upstream === dockerHub;
  const authorization = request.headers.get("Authorization");

  if (url.pathname === "/v2/") {
    const newUrl = new URL(upstream + "/v2/");
    const headers = new Headers();
    if (authorization) headers.set("Authorization", authorization);

    const resp = await fetch(newUrl.toString(), { method: "GET", headers, redirect: "follow" });
    if (resp.status === 401) return responseUnauthorized(url, MODE);
    return resp;
  }

  if (url.pathname === "/v2/auth") {
    const newUrl = new URL(upstream + "/v2/");
    const resp = await fetch(newUrl.toString(), { method: "GET", redirect: "follow" });
    if (resp.status !== 401) return resp;

    const authenticateStr = resp.headers.get("WWW-Authenticate");
    if (!authenticateStr) return resp;

    const wwwAuthenticate = parseAuthenticate(authenticateStr);
    let scope = url.searchParams.get("scope");

    if (scope && isDockerHub) {
      let scopeParts = scope.split(":");
      if (scopeParts.length === 3 && !scopeParts[1].includes("/")) {
        scopeParts[1] = "library/" + scopeParts[1];
        scope = scopeParts.join(":");
      }
    }
    return await fetchToken(wwwAuthenticate, scope, authorization);
  }

  if (isDockerHub) {
    const pathParts = url.pathname.split("/");
    if (pathParts.length === 5) {
      pathParts.splice(2, 0, "library");
      const redirectUrl = new URL(url);
      redirectUrl.pathname = pathParts.join("/");
      return Response.redirect(redirectUrl, 301);
    }
  }

  const newUrl = new URL(upstream + url.pathname);
  const newReq = new Request(newUrl, {
    method: request.method,
    headers: request.headers,
    redirect: isDockerHub ? "manual" : "follow",
  });

  const resp = await fetch(newReq);
  if (resp.status === 401) return responseUnauthorized(url, MODE);

  if (isDockerHub && resp.status === 307) {
    const location = new URL(resp.headers.get("Location"));
    return await fetch(location.toString(), { method: "GET", redirect: "follow" });
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

function responseUnauthorized(url, MODE) {
  const headers = new Headers();
  if (MODE === "debug") {
    headers.set("Www-Authenticate", `Bearer realm="http://${url.host}/v2/auth",service="cloudflare-docker-proxy"`);
  } else {
    headers.set("Www-Authenticate", `Bearer realm="https://${url.hostname}/v2/auth",service="cloudflare-docker-proxy"`);
  }
  return new Response(JSON.stringify({ message: "UNAUTHORIZED" }), { status: 401, headers });
}
