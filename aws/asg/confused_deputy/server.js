var express = require('express')
var serveIndex = require('serve-index')
var serveStatic = require('serve-static')

express()
  // serve markdown files with content-type: text/plain in Firefox
  .use((req, res, next) => {
    // by default serve-static serves markdown content with content-type: text/markdown
    if (
      /Firefox/.test(req.headers['user-agent']) &&
      // the default Path Matching RegExp in Markdown Viewer
      /\.(?:markdown|mdown|mkdn|md|mkd|mdwn|mdtxt|mdtext|text)(?:#.*|\?.*)?$/.test(req.url)
    ) {
      res.setHeader('content-type', 'text/plain; charset=utf-8')
    }
    next()
  })
  .use(serveStatic('/home/parallels/spikes/aws/asg/confused_deputy'))
  .use('/', serveIndex('/home/parallels/spikes/aws/asg/confused_deputy', {'icons': true, view: 'details'}))
  .listen(8000)
