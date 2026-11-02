/* Service worker da Agenda J&S
   - Arquivos do app: rede primeiro, cache como reserva (funciona offline)
   - /api/*: nunca em cache (sincronização sempre ao vivo)
*/
const CACHE = "agenda-js-v1";
const ESTATICOS = ["/", "/index.html", "/manifest.webmanifest", "/logo-joceir-silvia.png",
  "/icons/apple-touch-icon.png", "/icons/icon-192.png", "/icons/icon-512.png",
  "/icons/icon-maskable-192.png", "/icons/icon-maskable-512.png"];

self.addEventListener("install", ev => {
  ev.waitUntil(caches.open(CACHE).then(c => c.addAll(ESTATICOS)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", ev => {
  ev.waitUntil(
    caches.keys().then(chaves => Promise.all(
      chaves.filter(k => k !== CACHE).map(k => caches.delete(k))
    )).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", ev => {
  const url = new URL(ev.request.url);
  if (ev.request.method !== "GET" || url.pathname.startsWith("/api/")) return;
  ev.respondWith(
    fetch(ev.request)
      .then(resp => {
        if (resp.ok && url.origin === self.location.origin) {
          const copia = resp.clone();
          caches.open(CACHE).then(c => c.put(ev.request, copia));
        }
        return resp;
      })
      .catch(() => caches.match(ev.request).then(hit => hit || caches.match("/index.html")))
  );
});

/* Notificações recebidas por push (quando ativadas) abrem o app ao toque */
self.addEventListener("notificationclick", ev => {
  ev.notification.close();
  ev.waitUntil(self.clients.matchAll({ type: "window" }).then(lista => {
    for (const cliente of lista) { if ("focus" in cliente) return cliente.focus(); }
    return self.clients.openWindow("/");
  }));
});
