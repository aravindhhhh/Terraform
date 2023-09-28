function handler(event) {
  var request = event.request;
  var uri = request.uri;

  var subdomainName = undefined;

  if (request.headers.host && request.headers.host.value) {
    var hostname = request.headers.host.value

    var filepath = shouldReplacePath(uri) ? "/index.html" : uri;

    /*
    <pr-#>.app.<dev|staging>.meetalix.io
    */

    var subdomain = hostname.split(".")[0];
    var directory = subdomain.includes("app") ? "current" : subdomain

    request.uri = `/${directory}${filepath}`;
  }

  return request;
}
