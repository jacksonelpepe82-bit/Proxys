export default {
  async fetch(request, env) {

    const url = new URL(request.url)
    const pathname = url.pathname

    const channels = {
      "/canal1": env.CANAL1,
      "/canal2": env.CANAL2
    }

    const token = url.searchParams.get("token")
    const exp = url.searchParams.get("exp")
    const segmentUrl = url.searchParams.get("url")

    if (!token || !exp) {
      return new Response("Acceso inválido", { status: 403 })
    }

    if (Date.now() > parseInt(exp)) {
      return new Response("Token expirado", { status: 403 })
    }

    const data = pathname + exp
    const encoder = new TextEncoder()

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(env.SECRET_KEY),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    )

    const signature = await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(data)
    )

    const expectedToken = btoa(
      String.fromCharCode(...new Uint8Array(signature))
    )

    if (token !== expectedToken) {
      return new Response("Token incorrecto", { status: 403 })
    }

    if (segmentUrl) {
      const segmentResponse = await fetch(segmentUrl)
      return new Response(segmentResponse.body, {
        headers: {
          "Content-Type": segmentResponse.headers.get("content-type") || "application/octet-stream"
        }
      })
    }

    if (!channels[pathname]) {
      return new Response("Canal no existe", { status: 404 })
    }

    const target = channels[pathname]
    const response = await fetch(target)

    let text = await response.text()
    const base = target.substring(0, target.lastIndexOf("/") + 1)

    text = text.replace(/^(?!#)(.*)$/gm, (line) => {
      if (line.startsWith("http")) {
        return `${url.origin}${pathname}?token=${token}&exp=${exp}&url=${encodeURIComponent(line)}`
      } else if (line.trim() !== "") {
        return `${url.origin}${pathname}?token=${token}&exp=${exp}&url=${encodeURIComponent(base + line)}`
      }
      return line
    })

    return new Response(text, {
      headers: { "Content-Type": "application/vnd.apple.mpegurl" }
    })
  }
}
